# ✂️ elfstrip


<div align="center">

[![Platform](https://img.shields.io/badge/platform-Linux-blue?logo=linux&logoColor=white)](https://www.linux.org/)
[![Language](https://img.shields.io/badge/language-C-00599C?logo=c)](https://en.wikipedia.org/wiki/C_(programming_language))
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

*Extreme ELF metadata stripper — Remove everything non‑essential, keep execution*

</div>

> **⚠️ WARNING**  
> This tool is for educational purposes and authorized security auditing only.  
> The author is not responsible for any misuse.

---

## 📥 Download | Скачать

**Precompiled binary (Linux x86_64) is available in the release:**  
**Готовый бинарник (Linux x86_64) в релизе:**

👉 **[Download / Скачать elfstrip v2.0.0](https://github.com/vk-candpython/elfstrip/releases/tag/v2.0.0)** 👈

Go to **Assets** → click `elfstrip` → make executable:  
Перейдите в **Assets** → нажмите `elfstrip` → сделайте исполняемым:

```bash
chmod +x elfstrip
./elfstrip <your-elf-file>
```

---

## 📖 Table of Contents | Оглавление

- [English](#english)
  - [Overview](#overview)
  - [Features](#features)
  - [Quick Start](#quick-start)
  - [Example](#example)
  - [Requirements](#requirements)
  - [Troubleshooting](#troubleshooting)
- [Русский](#русский)
  - [Обзор](#обзор)
  - [Возможности](#возможности)
  - [Быстрый старт](#быстрый-старт)
  - [Пример](#пример)
  - [Требования](#требования)
  - [Устранение неполадок](#устранение-неполадок)

---

# English

## Overview

**elfstrip** — is an aggressive ELF binary stripper that removes **all non‑critical metadata** from Linux executables and shared objects. It goes far beyond standard `strip` or `sstrip`:

- **Zeroes out** section headers, making the file appear empty to `readelf -S`.
- **Compacts** program headers – non‑essential segments like `PT_NOTE` are removed, and the remaining headers are packed to the front.
- **Intelligently sanitizes** the dynamic table: removes `DT_DEBUG`, `DT_RPATH`, `DT_RUNPATH`, `DT_SONAME` (for executables), and zero‑value entries.
- **Preserves** everything that is truly required for execution: `PT_LOAD` (with BSS), `PT_DYNAMIC`, `PT_INTERP`, `PT_PHDR`, `PT_TLS`, `PT_GNU_RELRO`, `PT_GNU_STACK` (non‑empty), `PT_GNU_PROPERTY`, `PT_GNU_EH_FRAME` (if exceptions are used), and `PT_ARM_EXIDX`.
- **Detects C++ exceptions** by scanning for `_Unwind_Resume` inside `PT_LOAD` segments – if none is found, `.eh_frame` and ARM exception index tables are completely wiped.
- **Handles Intel CET/IBT/SHSTK safely** – `PT_GNU_PROPERTY` is never touched, even when overlapping `PT_NOTE` segments are removed.
- **Trims trailing zeros** from the end of every `PT_LOAD` segment, physically shrinking the file while preserving the full virtual memory size.
- **Wipes all gaps** between protected regions with zeros and truncates the file.
- **Preserves `e_flags`** on ARM/AArch64 and ARC targets to avoid breaking platform‑specific features.
- **Clears ELF identification padding** (`EI_OSABI` … `EI_NIDENT`) for a cleaner binary signature.
- **Aligns final truncation** to an 8‑byte boundary for optimal file system handling.
- **Outputs clear statistics**: old size, new size, and percentage reduction with one decimal.

The result: a **sectionless** ELF that runs exactly like the original but can be **10‑30 % smaller** (or even more for programs without C++ exceptions).

## Features

| Feature | Description |
|---------|-------------|
| 🗜️ **Program Header Compaction** | Removes non‑critical segments, packs surviving headers to the front |
| 🧠 **BSS‑aware LOAD handling** | If `p_memsz > p_filesz`, keeps original memory size → `.bss` preserved |
| 🔄 **PT_PHDR Synchronization** | Updates `p_filesz` and `p_memsz` after compaction |
| 🧹 **Dynamic Table Sanitization** | Drops `DT_DEBUG`, runtime paths, `DT_SONAME` for executables, and zero‑value entries |
| 🧬 **Smart EH‑Frame Removal** | Detects C++ exceptions via `_Unwind_Resume` scan; removes `.eh_frame` and `PT_ARM_EXIDX` only when no exceptions are used |
| 📉 **Section Header Removal** | Zeroes `e_shoff`, `e_shnum`, `e_shentsize`, `e_shstrndx` – makes ELF “sectionless” |
| 🛡️ **Safe NOTE Wiping** | Removes `PT_NOTE` while keeping overlapping `PT_GNU_PROPERTY` intact (Intel CET/IBT/SHSTK) |
| 📏 **Trailing Zero Truncation** | Cuts physical zeros at the end of every `PT_LOAD` segment, reducing file size |
| 🕳️ **Gap Wiping** | Fills all unmapped areas between critical segments with zeros |
| 🧬 **Architecture‑Agnostic** | Full support for x86 (32/64), ARM/AArch64, RISC‑V (via `PT_RISCV_ATTRIBUTES` if defined) |
| 🏳️ **`e_flags` Preservation** | Keeps `e_flags` intact on ARM, AArch64, and ARC targets |
| 🧽 **e_ident Cleanup** | Zeroes OS‑specific and padding bytes in ELF identification |
| 📐 **Alignment Truncation** | Aligns final file size to 8‑byte boundary with zero‑fill |
| 📊 **Statistics** | Prints old → new size in bytes and percentage reduction |
| 🔧 **In‑Place Modification** | Modifies target file directly (backup recommended) |
| ⚡ **No Dependencies** | Single C file, compiles with any standard C compiler |

## Quick Start

### Download precompiled binary (from release)

```bash
# Download from https://github.com/vk-candpython/elfstrip/releases/tag/v2.0.0
wget https://github.com/vk-candpython/elfstrip/releases/download/v2.0.0/elfstrip
chmod +x elfstrip
```

### Or compile from source

```bash
git clone https://github.com/vk-candpython/elfstrip.git
cd elfstrip
gcc -Os -s elfstrip.c -o elfstrip   # -Os -s minimizes binary size
```

### Usage

```bash
./elfstrip <elf-file>
```

> **⚠️ Caution:** Modifies the target file **in‑place** – make a backup if needed.

## Example

**Before stripping** – a typical dynamically linked executable:

```text
$ readelf -h main | grep "Number of section headers"
Number of section headers:         27
$ readelf -S main | wc -l
30
```

**After running `elfstrip main`:**

```text
$ ./elfstrip main
[+] Stripped: 8520 -> 6704 bytes (-21.3%)
```

```text
$ readelf -h main | grep "Number of section headers"
Number of section headers:         0
$ readelf -S main
  Section headers: NONE (0 sections)
$ readelf -l main      # program headers remain unchanged
  (same PHDR, INTERP, LOADx4, DYNAMIC, GNU_STACK, ...)
```

The binary executes exactly as before, but all section headers are gone.

## Requirements

| Requirement | Minimum | Notes |
|-------------|---------|-------|
| **OS** | Linux | any distribution |
| **Architecture** | x86, x86_64, ARM, AArch64, RISC‑V | 32/64‑bit |
| **Compiler** | GCC / Clang | only for source build |
| **File Size** | ≥ 1024 bytes | enforced by `MIN_ELF_SZ` |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `file size is below minimum ELF threshold` | Input file < 1 KB; refuse to process. |
| `invalid ELF file` | File does not conform to ELF format (e.g., wrong `e_phentsize`). |
| `unsupported ELF type` | Only `ET_EXEC` and `ET_DYN` are supported. `ET_REL` (object files) are not. |
| `msync` / `ftruncate` / `fsync` errors | Cannot write changes; check disk space/permissions. |
| Binary crashes after stripping | Original relied on non‑standard segments; modify `is_crit_seg()` to preserve more types. |

---

# Русский

## Обзор

**elfstrip** — это агрессивный стриппер ELF-бинарников, который удаляет **все некритичные метаданные** из исполняемых файлов и разделяемых библиотек Linux. Он идёт гораздо дальше стандартного `strip` или `sstrip`:

- **Зануляет** заголовки секций, делая файл пустым для `readelf -S`.
- **Уплотняет** программные заголовки – некритичные сегменты вроде `PT_NOTE` удаляются, а оставшиеся упаковываются в начало.
- **Интеллектуально очищает** динамическую таблицу: удаляет `DT_DEBUG`, `DT_RPATH`, `DT_RUNPATH`, `DT_SONAME` (для исполняемых файлов) и записи с нулевыми значениями.
- **Сохраняет** всё, что действительно необходимо для выполнения: `PT_LOAD` (с BSS), `PT_DYNAMIC`, `PT_INTERP`, `PT_PHDR`, `PT_TLS`, `PT_GNU_RELRO`, `PT_GNU_STACK` (непустой), `PT_GNU_PROPERTY`, `PT_GNU_EH_FRAME` (если используются исключения) и `PT_ARM_EXIDX`.
- **Определяет наличие C++ исключений**, сканируя `_Unwind_Resume` внутри `PT_LOAD` – если сигнатура не найдена, `.eh_frame` и таблицы исключений ARM полностью удаляются.
- **Безопасно работает с Intel CET/IBT/SHSTK** – `PT_GNU_PROPERTY` никогда не трогается, даже при удалении перекрывающихся `PT_NOTE`.
- **Обрезает хвостовые нули** в конце каждого `PT_LOAD` сегмента, физически уменьшая файл при сохранении полного виртуального размера.
- **Затирает все промежутки** между защищёнными регионами нулями и обрезает файл.
- **Сохраняет `e_flags`** на ARM/AArch64 и ARC, чтобы не сломать платформенно‑зависимые функции.
- **Очищает идентификационное поле ELF** (`EI_OSABI` … `EI_NIDENT`) для более чистого «отпечатка».
- **Выравнивает финальное усечение** по 8‑байтной границе с заполнением нулями.
- **Выводит понятную статистику**: старый размер, новый размер и процент уменьшения с одной десятой.

Результат: **бессекционный** ELF, который работает точно так же, как оригинал, но может быть на **10–30 % меньше** (а для программ без C++ исключений – ещё сильнее).

## Возможности

| Функция | Описание |
|---------|----------|
| 🗜️ **Уплотнение заголовков программ** | Удаляет некритичные сегменты, упаковывает оставшиеся в начало |
| 🧠 **Сохранение BSS у PT_LOAD** | Если `p_memsz > p_filesz`, оставляет исходный размер памяти – `.bss` не теряется |
| 🔄 **Синхронизация PT_PHDR** | Обновляет `p_filesz` и `p_memsz` после упаковки |
| 🧹 **Очистка динамической таблицы** | Удаляет `DT_DEBUG`, пути рантайма, `DT_SONAME` у исполняемых файлов и записи с нулевыми значениями |
| 🧬 **Умное удаление EH‑фреймов** | Определяет наличие исключений C++ по сигнатуре `_Unwind_Resume`; удаляет `.eh_frame` и `PT_ARM_EXIDX` только при отсутствии исключений |
| 📉 **Удаление заголовков секций** | Обнуляет `e_shoff`, `e_shnum`, `e_shentsize`, `e_shstrndx` – ELF становится «бессекционным» |
| 🛡️ **Безопасное удаление NOTE** | Удаляет `PT_NOTE`, сохраняя перекрывающийся `PT_GNU_PROPERTY` нетронутым (Intel CET/IBT/SHSTK) |
| 📏 **Обрезка хвостовых нулей** | Отрезает физические нули в конце каждого `PT_LOAD` сегмента, уменьшая размер файла |
| 🕳️ **Затирка промежутков** | Заполняет нулями все несоприкасающиеся области между критическими сегментами |
| 🧬 **Независимость от архитектуры** | Полная поддержка x86 (32/64), ARM/AArch64, RISC‑V (через `PT_RISCV_ATTRIBUTES` если определён) |
| 🏳️ **Сохранение `e_flags`** | Оставляет `e_flags` нетронутыми на ARM, AArch64 и ARC |
| 🧽 **Очистка e_ident** | Затирает специфичные для ОС и заполняющие байты в идентификации ELF |
| 📐 **Выравнивание усечения** | Выравнивает финальный размер файла до 8‑байтной границы с заполнением нулями |
| 📊 **Статистика** | Выводит старый и новый размер в байтах и процент уменьшения |
| 🔧 **Изменение на месте** | Изменяет файл напрямую (рекомендуется бэкап) |
| ⚡ **Нет зависимостей** | Один C-файл, компилируется любым компилятором C |

## Быстрый старт

### Скачать готовый бинарник (из релиза)

```bash
# Скачать с https://github.com/vk-candpython/elfstrip/releases/tag/v2.0.0
wget https://github.com/vk-candpython/elfstrip/releases/download/v2.0.0/elfstrip
chmod +x elfstrip
```

### Или собрать из исходников

```bash
git clone https://github.com/vk-candpython/elfstrip.git
cd elfstrip
gcc -Os -s elfstrip.c -o elfstrip   # -Os -s для минимального размера
```

### Использование

```bash
./elfstrip <elf-файл>
```

> **⚠️ Внимание:** Изменяет файл **на месте** – сделайте бэкап при необходимости.

## Пример

**До обработки** – обычный динамический исполняемый файл:

```text
$ readelf -h main | grep "Number of section headers"
Number of section headers:         27
$ readelf -S main | wc -l
30
```

**После `./elfstrip main`:**

```text
$ ./elfstrip main
[+] Stripped: 8520 -> 6704 bytes (-21.3%)
```

```text
$ readelf -h main | grep "Number of section headers"
Number of section headers:         0
$ readelf -S main
  Section headers: NONE (0 sections)
$ readelf -l main      # заголовки программ остались неизменными
  (те же PHDR, INTERP, LOADx4, DYNAMIC, GNU_STACK, ...)
```

Бинарник работает как раньше, но заголовки секций исчезли.

## Требования

| Требование | Минимум | Примечания |
|------------|---------|------------|
| **ОС** | Linux | любой дистрибутив |
| **Архитектура** | x86, x86_64, ARM, AArch64, RISC‑V | 32/64‑бит |
| **Компилятор** | GCC / Clang | только для сборки из исходников |
| **Размер файла** | ≥ 1024 байт | проверка `MIN_ELF_SZ` |

## Устранение неполадок

| Проблема | Решение |
|----------|---------|
| `file size is below minimum ELF threshold` | Входной файл < 1 КБ; обработка отклонена. |
| `invalid ELF file` | Файл не соответствует формату ELF (например, неверный `e_phentsize`). |
| `unsupported ELF type` | Поддерживаются только `ET_EXEC` и `ET_DYN`. `ET_REL` (объектные файлы) не поддерживаются. |
| Ошибки `msync` / `ftruncate` / `fsync` | Не удалось записать изменения; проверьте место на диске и права доступа. |
| Бинарник падает после обработки | Исходный файл использовал нестандартные сегменты; измените `is_crit_seg()` для сохранения дополнительных типов. |

---

<div align="center">

**[⬆ Back to Top / Наверх](#-elfstrip)**

*Extreme ELF stripping for Linux*

</div>
