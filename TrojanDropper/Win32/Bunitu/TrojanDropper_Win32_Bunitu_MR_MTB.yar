
rule TrojanDropper_Win32_Bunitu_MR_MTB{
	meta:
		description = "TrojanDropper:Win32/Bunitu.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {5e 8b e5 5d c3 90 0a 1e 00 03 05 90 01 04 0f be 90 01 01 30 f7 90 01 01 8b 90 01 01 f8 0f be 90 01 01 2b 90 01 01 8b 90 01 01 f8 88 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}