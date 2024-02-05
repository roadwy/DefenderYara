
rule Trojan_Win32_Zenpack_NEAD_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.NEAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 08 89 45 f8 8b 45 f8 89 45 f4 8b 45 f4 0f b6 00 3d ff 00 00 00 74 15 eb 36 8a 45 f3 24 01 0f b6 c8 89 4d fc 8b 45 fc 83 c4 14 5d } //05 00 
		$a_01_1 = {77 00 65 00 72 00 65 00 2e 00 6f 00 6e 00 65 00 36 00 6d 00 75 00 6c 00 74 00 69 00 70 00 6c 00 79 00 6c 00 63 00 72 00 65 00 61 00 74 00 75 00 72 00 65 00 2e 00 } //00 00 
	condition:
		any of ($a_*)
 
}