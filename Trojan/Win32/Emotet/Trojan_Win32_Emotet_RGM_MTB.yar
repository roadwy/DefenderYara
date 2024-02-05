
rule Trojan_Win32_Emotet_RGM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RGM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {f7 f1 8b 45 90 01 01 0f be 0c 10 8b 55 90 01 01 0f b6 84 15 90 01 04 33 c1 8b 4d 90 01 01 88 84 0d 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}