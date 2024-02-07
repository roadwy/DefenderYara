
rule Trojan_Win32_Smokeloader_MBFN_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.MBFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 55 f8 88 55 ff 0f b6 45 ff 05 90 01 04 88 45 ff 0f b6 4d ff f7 d9 88 4d ff 0f b6 55 ff 83 c2 6b 88 55 ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 4d ff f7 d1 88 4d ff 0f b6 55 ff 90 00 } //01 00 
		$a_01_1 = {42 4c 46 4f 49 4f 43 51 49 4f 57 56 4a 41 49 53 48 4a 49 41 4a 49 48 58 } //00 00  BLFOIOCQIOWVJAISHJIAJIHX
	condition:
		any of ($a_*)
 
}