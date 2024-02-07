
rule Trojan_Win32_NSISInject_DH_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 8d ff fb ff ff 0f b6 b5 ff fb ff ff c1 fe 90 01 01 0f b6 bd ff fb ff ff c1 e7 90 01 01 89 f1 09 f9 88 8d ff fb ff ff 90 02 07 0f b6 b5 ff fb ff ff 89 90 00 } //01 00 
		$a_81_1 = {49 63 6f 4c 65 51 } //00 00  IcoLeQ
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInject_DH_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {89 45 fc 6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 55 fc } //01 00 
		$a_03_1 = {c1 f9 06 0f b6 15 90 01 04 c1 e2 02 0b ca 88 0d 90 01 04 0f b6 05 90 09 1f 00 88 15 90 01 04 0f b6 05 90 01 04 2b 05 90 01 04 a2 90 01 04 0f b6 0d 90 00 } //01 00 
		$a_03_2 = {f7 d1 88 0d 90 01 04 0f b6 15 90 01 04 c1 fa 02 0f b6 05 90 01 04 c1 e0 06 0b d0 88 15 90 01 04 0f b6 0d 90 09 0c 00 a2 90 01 04 0f b6 0d 90 00 } //01 00 
		$a_03_3 = {c1 fa 07 0f b6 05 90 01 04 d1 e0 0b d0 88 15 90 01 04 0f b6 0d 90 09 1f 00 a2 90 01 04 0f b6 0d 90 01 04 33 0d 90 01 04 88 0d 90 01 04 0f b6 15 90 00 } //01 00 
		$a_03_4 = {f7 d2 88 15 90 01 04 0f b6 05 90 01 04 c1 f8 07 0f b6 0d 90 01 04 d1 e1 0b c1 a2 90 01 04 0f b6 15 90 09 1f 00 a2 90 01 04 0f b6 0d 90 01 04 33 0d 90 01 04 88 0d 90 01 04 0f b6 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}