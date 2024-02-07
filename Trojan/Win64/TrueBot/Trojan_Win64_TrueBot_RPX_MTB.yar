
rule Trojan_Win64_TrueBot_RPX_MTB{
	meta:
		description = "Trojan:Win64/TrueBot.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 68 00 6b 00 64 00 73 00 6b 00 45 00 78 00 73 00 } //01 00  ChkdskExs
		$a_01_1 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 48 00 61 00 63 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  ProcessHacker.exe
		$a_01_2 = {52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 48 00 61 00 63 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  ResourceHacker.exe
		$a_01_3 = {70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 65 78 65 63 75 74 69 6f 6e 70 6f 6c 69 63 79 20 62 79 70 61 73 73 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e 20 25 73 } //01 00  process call create "powershell -executionpolicy bypass -nop -w hidden %s
		$a_01_4 = {50 4f 53 54 20 25 73 20 48 54 54 50 2f 31 2e 30 } //01 00  POST %s HTTP/1.0
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //01 00  ShellExecuteExA
		$a_01_6 = {77 6d 69 63 2e 65 78 65 } //01 00  wmic.exe
		$a_01_7 = {25 73 5c 25 30 38 78 2d 25 30 38 78 2e 70 73 31 } //00 00  %s\%08x-%08x.ps1
	condition:
		any of ($a_*)
 
}