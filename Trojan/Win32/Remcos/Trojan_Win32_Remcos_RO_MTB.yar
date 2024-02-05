
rule Trojan_Win32_Remcos_RO_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 04 0a 34 90 01 01 04 90 01 01 34 90 01 01 2c 90 01 01 88 01 41 83 ee 01 75 90 01 01 68 de c0 ad de 90 00 } //01 00 
		$a_02_1 = {8a 04 0a 34 90 01 01 2c 90 01 01 34 90 01 01 2c 90 01 01 88 01 41 83 ee 01 75 90 01 01 68 de c0 ad de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Remcos_RO_MTB_2{
	meta:
		description = "Trojan:Win32/Remcos.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {85 db 66 81 fb ee 00 ff 37 83 ff 90 01 01 66 83 fa 90 01 01 66 81 fa 90 01 02 66 83 fb 90 01 01 85 d2 81 fb 90 01 04 5f 66 81 fb 90 01 02 66 a9 90 01 02 81 ff 90 01 04 66 3d 90 01 02 66 85 d2 83 f8 90 01 01 66 85 d2 66 83 ff 90 01 01 31 f7 66 83 fa 90 01 01 66 85 d2 81 fa 90 01 04 83 ff 90 01 01 66 83 f8 90 01 01 85 c0 89 3c 10 85 c0 85 db 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}