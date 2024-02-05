
rule Trojan_Win32_Emotet_PVJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {8a 5d 00 8b 44 24 10 83 c0 f0 c7 84 24 90 01 04 ff ff ff ff 8d 48 0c 8a 54 14 14 32 da 88 5d 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}