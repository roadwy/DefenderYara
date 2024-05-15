
rule Trojan_Win32_LummaC_GAA_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 30 0c 06 83 ff 90 01 03 6a 00 6a 00 6a 00 ff d3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}