
rule Trojan_Win32_Totbrick_C{
	meta:
		description = "Trojan:Win32/Totbrick.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 3e 2a 75 03 46 8b fe 8a 13 3a 16 74 04 8b f7 eb } //1
		$a_01_1 = {52 50 53 66 c7 45 e4 58 68 66 c7 45 ea 50 e9 } //1
		$a_01_2 = {83 c0 41 66 89 04 53 8b 45 fc 66 83 3c 43 46 76 0c b9 e9 ff 00 00 66 01 0c 43 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}