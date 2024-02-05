
rule Trojan_Win32_Redline_NXT_MTB{
	meta:
		description = "Trojan:Win32/Redline.NXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 fc b8 90 01 04 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}