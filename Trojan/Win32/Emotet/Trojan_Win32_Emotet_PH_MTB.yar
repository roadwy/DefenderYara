
rule Trojan_Win32_Emotet_PH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 57 a1 90 01 03 00 a3 90 01 03 00 8b 0d 90 01 03 00 8b 11 89 15 90 01 03 00 a1 90 01 03 00 2d 59 2f 00 00 a3 90 01 03 00 8b 0d 90 01 03 00 81 c1 59 2f 00 00 a1 90 01 03 00 a3 90 01 03 00 a1 90 01 03 00 31 0d 90 01 03 00 8b ff c7 05 90 01 03 00 00 00 00 00 a1 90 01 03 00 01 05 90 01 03 00 8b ff 5f 5d c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}