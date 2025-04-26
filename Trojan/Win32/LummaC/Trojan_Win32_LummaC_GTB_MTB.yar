
rule Trojan_Win32_LummaC_GTB_MTB{
	meta:
		description = "Trojan:Win32/LummaC.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e 24 00 00 50 ?? 00 00 4c 01 07 00 32 34 d0 67 00 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}