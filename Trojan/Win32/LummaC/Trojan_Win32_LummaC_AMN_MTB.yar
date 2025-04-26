
rule Trojan_Win32_LummaC_AMN_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c2 0f b6 c0 89 44 24 [0-28] e8 ?? ?? ?? ?? 8b 44 24 ?? 8b 4c 24 ?? 8a 44 04 ?? 30 04 19 43 3b 5d 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}