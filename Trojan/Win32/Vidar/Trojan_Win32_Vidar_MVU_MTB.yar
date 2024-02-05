
rule Trojan_Win32_Vidar_MVU_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MVU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {40 89 46 04 89 85 5c fb ff ff c1 e8 18 33 c7 25 ff 00 00 00 c1 ef 08 89 0e 33 3c 85 b0 5c 44 00 8b c7 8b bd 60 fb ff ff 8b df 83 f3 01 0f af df c1 eb 08 32 9d 68 fb ff ff 89 46 08 88 5c 15 db 89 95 60 fb ff ff 83 fa 0c 0f 8c dd fd ff ff } //00 00 
	condition:
		any of ($a_*)
 
}