
rule Trojan_Win32_Tibs_JD{
	meta:
		description = "Trojan:Win32/Tibs.JD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 55 f4 52 51 6a 04 57 ff 55 fc 90 09 14 00 0f 6f 90 01 01 89 c1 0f 7e 90 01 01 fc b9 90 01 04 81 f1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}