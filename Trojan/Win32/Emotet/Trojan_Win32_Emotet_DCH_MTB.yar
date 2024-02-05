
rule Trojan_Win32_Emotet_DCH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 14 00 "
		
	strings :
		$a_02_0 = {33 d2 8a 11 03 c2 99 b9 90 01 04 f7 f9 90 00 } //14 00 
		$a_02_1 = {55 8b ec 8b 45 90 01 01 0b 45 90 01 01 8b 4d 90 01 01 f7 d1 8b 55 90 01 01 f7 d2 0b ca 23 c1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}