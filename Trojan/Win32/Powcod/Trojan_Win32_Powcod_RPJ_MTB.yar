
rule Trojan_Win32_Powcod_RPJ_MTB{
	meta:
		description = "Trojan:Win32/Powcod.RPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //1 cmd.exe
		$a_01_1 = {48 00 69 00 64 00 64 00 65 00 6e 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 Hidden powershell
		$a_01_2 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 } //1 Invoke-webrequest
		$a_01_3 = {67 00 72 00 61 00 6e 00 74 00 61 00 62 00 6c 00 65 00 2d 00 65 00 78 00 63 00 65 00 73 00 73 00 65 00 73 00 2e 00 30 00 30 00 30 00 77 00 65 00 62 00 68 00 6f 00 73 00 74 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 69 00 6e 00 64 00 65 00 78 00 } //1 grantable-excesses.000webhostapp.com/index
		$a_01_4 = {2e 00 74 00 78 00 74 00 } //1 .txt
		$a_01_5 = {55 00 73 00 65 00 42 00 61 00 73 00 69 00 63 00 50 00 61 00 72 00 73 00 69 00 6e 00 67 00 } //1 UseBasicParsing
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}