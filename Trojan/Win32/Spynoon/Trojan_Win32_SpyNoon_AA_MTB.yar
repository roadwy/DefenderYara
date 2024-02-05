
rule Trojan_Win32_SpyNoon_AA_MTB{
	meta:
		description = "Trojan:Win32/SpyNoon.AA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 f9 03 0f b6 55 ff c1 e2 05 0b ca 88 4d ff 0f b6 45 ff 05 9e 00 00 00 88 45 ff 0f b6 4d ff 33 4d f8 88 4d ff 0f b6 55 ff c1 fa 06 0f b6 45 ff c1 e0 02 0b d0 88 55 ff } //00 00 
	condition:
		any of ($a_*)
 
}