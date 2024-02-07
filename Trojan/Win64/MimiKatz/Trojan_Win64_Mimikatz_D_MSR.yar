
rule Trojan_Win64_Mimikatz_D_MSR{
	meta:
		description = "Trojan:Win64/Mimikatz.D!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 20 67 67 2e 6c 6e 6b } //01 00  start gg.lnk
		$a_01_1 = {73 65 6b 75 72 6c 73 61 3a 3a 6c 6f 67 6f 6e 70 61 73 73 77 6f 72 64 73 } //01 00  sekurlsa::logonpasswords
		$a_01_2 = {73 74 61 72 74 20 70 72 6f 63 64 75 6d 70 2e 65 78 65 20 2d 61 63 63 65 70 74 65 75 6c 61 20 2d 6d 61 20 6c 73 61 73 73 2e 65 78 65 20 6c 73 61 73 73 2e 64 6d 70 } //01 00  start procdump.exe -accepteula -ma lsass.exe lsass.dmp
		$a_01_3 = {65 78 70 61 6e 64 20 6d 69 6d 20 6d 69 6d 69 2e 65 78 65 } //01 00  expand mim mimi.exe
		$a_01_4 = {6d 69 6d 69 2e 65 78 65 73 74 6f 70 } //01 00  mimi.exestop
		$a_01_5 = {73 68 61 79 6b 68 65 6c 69 73 6c 61 6d 6f 76 2f 44 6f 63 75 6d 65 6e 74 73 2f 43 6f 64 65 74 65 73 74 2f 74 65 73 74 70 72 6f 6a 65 63 74 2f 6d 61 69 6e 2f 65 78 65 63 2e 67 6f } //00 00  shaykhelislamov/Documents/Codetest/testproject/main/exec.go
	condition:
		any of ($a_*)
 
}