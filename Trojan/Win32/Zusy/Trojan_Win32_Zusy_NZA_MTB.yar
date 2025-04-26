
rule Trojan_Win32_Zusy_NZA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 85 cc ff ff ff ?? ?? ?? ?? 8b 3e c7 85 f0 ff ff ff ?? ?? ?? ?? 33 fb 81 85 dc ff ff ff ?? ?? ?? ?? 89 3a 29 95 fc ff ff ff } //5
		$a_01_1 = {57 59 2a 44 55 5b 50 } //1 WY*DU[P
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win32_Zusy_NZA_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.NZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 57 75 05 e8 0c fb ff ff 8b 35 ?? ?? ?? ?? 33 ff 8a 06 3a c3 74 12 } //5
		$a_03_1 = {e8 3c dd ff ff 59 8d 74 06 ?? eb e8 8d 04 bd ?? ?? ?? ?? 50 e8 6f cb ff ff } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}