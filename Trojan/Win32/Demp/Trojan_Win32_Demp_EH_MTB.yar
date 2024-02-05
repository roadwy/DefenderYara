
rule Trojan_Win32_Demp_EH_MTB{
	meta:
		description = "Trojan:Win32/Demp.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 16 8d 76 01 0f b6 44 37 ff 02 c2 02 d8 0f b6 c3 03 c8 ff 8d f8 fe ff ff 0f b6 01 88 46 ff 88 11 8b 8d f4 fe ff ff 75 d7 } //00 00 
	condition:
		any of ($a_*)
 
}