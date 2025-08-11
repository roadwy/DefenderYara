
rule Trojan_Win32_LummaC_GH_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 1c 0a 30 c3 88 1c 0a 41 39 8c 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}