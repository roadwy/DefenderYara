
rule Trojan_Win32_Witch_BH_MTB{
	meta:
		description = "Trojan:Win32/Witch.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 55 f4 03 55 08 0f b6 02 33 c1 8b 4d f4 03 4d 08 88 01 e9 } //00 00 
	condition:
		any of ($a_*)
 
}