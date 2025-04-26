
rule Trojan_Win32_StealC_GA_MTB{
	meta:
		description = "Trojan:Win32/StealC.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 14 38 83 fb 0f 75 90 09 0c 00 8a 95 [0-04] 8b 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}