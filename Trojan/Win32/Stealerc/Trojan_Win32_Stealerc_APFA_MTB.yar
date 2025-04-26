
rule Trojan_Win32_Stealerc_APFA_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.APFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 75 fc 89 75 dc 8b 45 dc 29 45 f8 81 c7 47 86 c8 61 83 6d ?? 01 0f 85 } //3
		$a_01_1 = {8b c3 c1 e8 05 89 45 fc 8b 45 e8 01 45 fc 8b f3 c1 e6 04 03 75 ec 8d 0c 1f 33 f1 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}