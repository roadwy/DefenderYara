
rule Trojan_Win32_Rastreio_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Rastreio.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 65 63 68 6f 20 6f 66 66 } //01 00  @echo off
		$a_01_1 = {73 65 74 6c 6f 63 61 6c 20 45 6e 61 62 6c 65 44 65 6c 61 79 65 64 45 78 70 61 6e 73 69 6f 6e } //01 00  setlocal EnableDelayedExpansion
		$a_03_2 = {5e 53 5e 65 5e 74 20 90 02 02 3d 5e 53 5e 65 5e 74 90 00 } //01 00 
		$a_01_3 = {2e 00 62 00 61 00 74 00 } //01 00  .bat
		$a_01_4 = {2d 77 69 20 31 20 2d } //01 00  -wi 1 -
		$a_01_5 = {77 72 69 74 65 2d 68 6f 73 74 20 24 65 6e 76 3a } //01 00  write-host $env:
		$a_01_6 = {64 65 6c 20 22 25 7e 66 30 22 } //0a 00  del "%~f0"
		$a_01_7 = {21 3a 2f 2f 21 } //0a 00  !://!
		$a_01_8 = {21 2f 5e 22 2c 5e 22 21 } //0a 00  !/^",^"!
		$a_01_9 = {21 5e 22 29 20 5e 7c 20 2e 28 24 21 } //00 00  !^") ^| .($!
	condition:
		any of ($a_*)
 
}