
rule Trojan_Win32_Redline_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 55 8b ec 8b 45 08 8b 4d 0c 31 08 5d c2 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}