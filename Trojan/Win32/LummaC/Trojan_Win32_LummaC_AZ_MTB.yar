
rule Trojan_Win32_LummaC_AZ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 10 83 c0 ?? 89 44 24 ?? 83 6c 24 ?? ?? 8a 44 24 ?? 30 04 2f 83 fb 0f 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}