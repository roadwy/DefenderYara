
rule Trojan_Win32_Redline_GCP_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 3c 2e 8b c6 83 e0 03 68 90 01 04 8a 98 90 01 04 32 df e8 90 01 04 2a df 00 1c 2e 46 59 3b f7 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}