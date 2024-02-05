
rule Trojan_Win32_Emotet_DBJ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {f7 f7 8b fa 0f b6 54 3c 90 01 01 88 54 34 90 01 01 88 4c 3c 90 01 01 0f b6 44 34 90 01 01 0f b6 c9 03 c1 99 b9 90 01 04 f7 f9 0f b6 54 14 90 01 01 30 53 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}