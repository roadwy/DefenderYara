
rule Trojan_Win32_Redline_GEG_MTB{
	meta:
		description = "Trojan:Win32/Redline.GEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 90 01 01 8a 98 90 01 04 32 df e8 90 01 04 8b f8 8b 0f 8b 49 90 01 01 8b 4c 39 90 01 01 8b 49 90 01 01 89 4c 24 90 01 01 8b 11 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}