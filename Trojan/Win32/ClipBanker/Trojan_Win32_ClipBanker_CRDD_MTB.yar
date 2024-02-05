
rule Trojan_Win32_ClipBanker_CRDD_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.CRDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {c6 06 00 e8 90 01 04 6a 3a 88 46 01 e8 90 01 04 6a 5c 88 46 02 e8 90 01 04 6a 50 88 46 03 e8 90 01 04 6a 72 5b 53 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}