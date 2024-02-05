
rule Trojan_Win32_Redline_GNA_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 f6 17 80 07 90 01 01 47 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}