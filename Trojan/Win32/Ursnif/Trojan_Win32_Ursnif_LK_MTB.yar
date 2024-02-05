
rule Trojan_Win32_Ursnif_LK_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 4d fc 0d 8b 45 08 0f b6 00 3c 60 7e 0e 8b 45 08 0f b6 00 0f be c0 83 e8 20 eb 09 8b 45 08 0f b6 00 0f be c0 01 45 fc 83 45 08 01 8b 45 08 0f b6 00 84 c0 75 ca } //00 00 
	condition:
		any of ($a_*)
 
}