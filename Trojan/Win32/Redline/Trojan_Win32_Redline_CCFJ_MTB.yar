
rule Trojan_Win32_Redline_CCFJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 ff 15 90 01 03 00 c7 45 fc 90 01 04 8b 45 fc 50 c3 90 00 } //01 00 
		$a_03_1 = {50 6a 40 8b 0d 90 01 04 51 68 90 01 04 ff 55 90 01 01 89 45 90 01 01 8b 15 90 01 04 52 68 90 01 04 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}