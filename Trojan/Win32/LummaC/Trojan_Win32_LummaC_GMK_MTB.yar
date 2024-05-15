
rule Trojan_Win32_LummaC_GMK_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {f6 17 80 07 90 01 01 b8 90 01 04 b8 90 01 04 80 2f 90 01 01 f6 2f 47 e2 90 00 } //0a 00 
		$a_03_1 = {f6 17 80 07 90 01 01 b8 90 01 04 bb 90 01 04 b8 90 01 04 80 2f 90 01 01 f6 2f 47 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}