
rule Trojan_Win32_Winnti_O_dha{
	meta:
		description = "Trojan:Win32/Winnti.O!dha,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 63 72 79 70 74 62 61 73 65 2e 64 6c 6c } //1 %s\cryptbase.dll
		$a_01_1 = {73 79 73 70 72 65 70 2e 65 78 65 } //1 sysprep.exe
		$a_01_2 = {73 74 61 72 74 20 25 73 0d 0a 20 64 65 6c 20 25 25 30 00 } //1
		$a_01_3 = {61 76 70 2e 65 78 65 00 } //1
		$a_01_4 = {6d 73 69 65 78 65 63 2e 65 78 65 00 74 61 67 00 76 65 72 00 67 72 6f 75 70 00 00 00 75 72 6c 00 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10) >=12
 
}