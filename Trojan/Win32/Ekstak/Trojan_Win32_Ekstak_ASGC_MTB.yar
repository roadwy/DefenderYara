
rule Trojan_Win32_Ekstak_ASGC_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 e8 03 00 00 68 e8 03 00 00 68 c9 04 00 00 56 ff d7 85 c0 7e 07 50 ff 15 90 01 03 00 6a 00 6a 00 6a 4a 56 ff d7 90 00 } //2
		$a_03_1 = {55 8b ec 83 ec 0c 53 56 57 68 90 01 02 4c 00 e8 90 01 03 ff 89 45 fc e9 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}