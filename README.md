# ✂️ elfstrip


<div align="center">

[![Platform](https://img.shields.io/badge/platform-Linux-blue?logo=linux&logoColor=white)](https://www.linux.org/)
[![Language](https://img.shields.io/badge/language-C-00599C?logo=c)](https://en.wikipedia.org/wiki/C_(programming_language))
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

*Extreme ELF metadata stripper — Remove section headers, keep execution*

</div>

> **⚠️ WARNING**  
> This tool is for educational purposes and authorized security auditing only.  
> The author is not responsible for any misuse.

---

## 📥 Download | Скачать

**Precompiled binary (Linux x86_64) is available in the release:**  
**Готовый бинарник (Linux x86_64) в релизе:**

👉 **[Download / Скачать elfstrip v1.0.0](https://github.com/vk-candpython/elfstrip/releases/tag/v1.0.0)** 👈

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

**elfstrip** — is an aggressive ELF binary stripper that removes **all non‑critical metadata** from Linux executables and shared objects. Unlike standard `strip` or even `sstrip`, it **zeroes out** section headers, compacts program headers, sanitizes dynamic tables, and produces a minimal *ghost* ELF that executes correctly but appears empty to standard analysis tools (`readelf`, `objdump`, `gdb`). The resulting binary is typically **~16 KB** in size.

- Preserves only essential segments (`LOAD`, `DYNAMIC`, `INTERP`, `PHDR`, `GNU_*`).
- **Compacts** program headers and updates `PT_PHDR` (both size **and** offset → `e_phoff`).
- **Zeros** section header table and all ELF header fields that are not mandatory for execution.
- **Sanitizes** `PT_INTERP` (truncates trailing garbage) and `PT_DYNAMIC` (removes `DT_DEBUG`, `DT_RPATH`, `DT_RUNPATH` and zero‑value entries, preserves `DT_TEXTREL`/`DT_BIND_NOW`).
- **Wipes** all gaps between preserved regions with zeroes and truncates the file.

The result: an ELF with **all necessary program headers intact** but **no section headers** – a “sectionless” binary that runs exactly like the original.

## Features

| Feature | Description |
|---------|-------------|
| 🗜️ **Program Header Compaction** | Removes non‑critical segments, packs surviving headers to the front |
| 🔄 **PT_PHDR Synchronization** | Updates `p_filesz`, `p_memsz` **and** sets `p_offset = e_phoff` (correct file offset) |
| 🧹 **Dynamic Table Sanitization** | Filters `PT_DYNAMIC`: drops `DT_DEBUG`, `DT_RPATH`, `DT_RUNPATH`, zero‑value entries (preserves `DT_TEXTREL`, `DT_BIND_NOW`, `DT_NULL`) |
| 📉 **Section Header Removal** | Zeroes `e_shoff`, `e_shnum`, `e_shentsize`, `e_shstrndx` – makes ELF “sectionless” |
| 🕳️ **Gap Wiping** | Fills all unmapped areas between critical segments with zeroes |
| 📏 **Physical Truncation** | Shrinks the file to the last byte of the last preserved segment |
| 🏛️ **Architecture‑Agnostic** | Full support for x86 (32/64), ARM/AArch64, RISC‑V (via `PT_RISCV_ATTRIBUTES` if defined) |
| 🔧 **In‑Place Modification** | Modifies target file directly (backup recommended) |
| ⚡ **No Dependencies** | Single C file, compiles with any standard C compiler |

## Quick Start

### Download precompiled binary (from release)

```bash
# Download from https://github.com/vk-candpython/elfstrip/releases/tag/v1.0.0
wget https://github.com/vk-candpython/elfstrip/releases/download/v1.0.0/elfstrip
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
| `file is small for striping ELF` | Input file < 1 KB; refuse to process. |
| `invalid ELF file` | File does not conform to ELF format (e.g., wrong `e_phentsize`). |
| `unsupported ELF type` | Only `ET_EXEC` and `ET_DYN` are supported. `ET_REL` (object files) are not. |
| `msync` / `ftruncate` / `fsync` errors | Cannot write changes; check disk space/permissions. |
| Binary crashes after stripping | Original relied on non‑standard segments; modify `is_crit_seg()` to preserve more types. |

---

# Русский

## Обзор

**elfstrip** — это агрессивный стриппер ELF-бинарников, который удаляет **все некритичные метаданные** из исполняемых файлов и разделяемых библиотек Linux. В отличие от стандартного `strip` или даже `sstrip`, он **зануляет** заголовки секций, уплотняет заголовки программ, санирует динамические таблицы и создаёт минимальный «призрачный» ELF, который корректно выполняется, но выглядит пустым для стандартных анализаторов (`readelf`, `objdump`, `gdb`). Итоговый бинарник весит **около 16 КБ**.

## Возможности

| Функция | Описание |
|---------|----------|
| 🗜️ **Уплотнение заголовков программ** | Удаляет некритичные сегменты, упаковывает оставшиеся в начало |
| 🔄 **Синхронизация PT_PHDR** | Обновляет `p_filesz`, `p_memsz` **и** устанавливает `p_offset = e_phoff` (правильное смещение) |
| 🧹 **Очистка динамической таблицы** | Удаляет `DT_DEBUG`, `DT_RPATH`, `DT_RUNPATH` и записи с нулевыми значениями (сохраняет `DT_TEXTREL`, `DT_BIND_NOW`, `DT_NULL`) |
| 📉 **Удаление заголовков секций** | Обнуляет `e_shoff`, `e_shnum`, `e_shentsize`, `e_shstrndx` — ELF становится «бессекционным» |
| 🕳️ **Затирка промежутков** | Заполняет нулями все области между критическими сегментами |
| 📏 **Физическое урезание** | Уменьшает файл до последнего байта последнего сохранённого сегмента |
| 🏛️ **Независимость от архитектуры** | Полная поддержка x86 (32/64), ARM/AArch64, RISC‑V (через `PT_RISCV_ATTRIBUTES` если определён) |
| 🔧 **Изменение на месте** | Изменяет файл напрямую (рекомендуется бэкап) |
| ⚡ **Нет зависимостей** | Один C-файл, компилируется любым компилятором C |

## Быстрый старт

### Скачать готовый бинарник (из релиза)

```bash
# Скачать с https://github.com/vk-candpython/elfstrip/releases/tag/v1.0.0
wget https://github.com/vk-candpython/elfstrip/releases/download/v1.0.0/elfstrip
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
| `file is small for striping ELF` | Входной файл < 1 КБ; обработка отклонена. |
| `invalid ELF file` | Файл не соответствует формату ELF (например, неверный `e_phentsize`). |
| `unsupported ELF type` | Поддерживаются только `ET_EXEC` и `ET_DYN`. `ET_REL` (объектные файлы) не поддерживаются. |
| Ошибки `msync` / `ftruncate` / `fsync` | Не удалось записать изменения; проверьте место на диске и права доступа. |
| Бинарник падает после обработки | Исходный файл использовал нестандартные сегменты; измените `is_crit_seg()` для сохранения дополнительных типов. |

---

<div align="center">

**[⬆ Back to Top / Наверх](#-elfstrip)**

*Extreme ELF stripping for Linux*

</div>
