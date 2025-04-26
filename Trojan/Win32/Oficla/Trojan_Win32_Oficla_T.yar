
rule Trojan_Win32_Oficla_T{
	meta:
		description = "Trojan:Win32/Oficla.T,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 05 00 00 "
		
	strings :
		$a_03_0 = {8d 55 ec b8 53 00 00 00 e8 ?? ?? ?? ?? ff 75 ec 8d 55 ?? b8 (59|6f) 00 00 00 } //20
		$a_03_1 = {8a 0c 03 80 f1 ?? 88 0c 03 40 4a 75 f3 } //10
		$a_01_2 = {8a 14 03 80 f2 0d 88 14 03 40 4e 75 f3 } //10
		$a_01_3 = {8a 0c 13 80 f1 0d 88 0c 13 42 48 75 f3 } //10
		$a_01_4 = {75 73 65 72 69 6e 69 74 78 78 2e 65 78 65 00 } //1
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1) >=30
 
}