
rule Trojan_Win32_LummaC_ADHA_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ADHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 c1 ea 05 89 55 f8 8b 45 e4 01 45 f8 8b 45 f0 c1 e6 04 03 75 d8 8d 0c 03 33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}