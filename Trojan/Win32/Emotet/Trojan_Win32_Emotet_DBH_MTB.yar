
rule Trojan_Win32_Emotet_DBH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 ff d6 90 01 04 f7 90 02 03 8b 44 24 14 8a 0c 50 8a 14 90 02 05 32 d1 88 14 1f 47 3b 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}