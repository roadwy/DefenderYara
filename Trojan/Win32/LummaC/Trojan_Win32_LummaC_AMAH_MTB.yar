
rule Trojan_Win32_LummaC_AMAH_MTB{
	meta:
		description = "Trojan:Win32/LummaC.AMAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 00 8b 4d ?? 83 c1 ?? 0f be c9 33 c1 8b 4d [0-04] 03 4d ?? 88 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}