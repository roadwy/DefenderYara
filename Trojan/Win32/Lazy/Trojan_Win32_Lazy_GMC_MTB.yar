
rule Trojan_Win32_Lazy_GMC_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 83 c4 04 68 90 01 04 83 c4 04 32 02 90 01 01 88 07 47 83 ec 04 c7 04 24 90 01 04 83 c4 04 89 c0 52 83 04 24 01 5a 68 90 01 04 83 c4 04 68 90 01 04 83 c4 04 41 83 e9 02 89 c0 90 01 01 85 c9 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}