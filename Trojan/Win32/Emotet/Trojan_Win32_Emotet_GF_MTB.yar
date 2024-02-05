
rule Trojan_Win32_Emotet_GF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b c1 8b 4d 90 01 01 0f b6 04 01 8b 4d 90 01 01 0f b6 14 11 33 d0 a1 90 01 04 0f af 05 90 01 04 8b 0d 90 01 04 0f af 0d 90 01 04 8b 75 90 01 01 2b 35 90 01 04 03 35 90 01 04 03 35 90 01 04 2b 35 90 01 04 2b f1 2b 35 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}