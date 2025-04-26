
rule Trojan_Win32_LummaC_CCIR_MTB{
	meta:
		description = "Trojan:Win32/LummaC.CCIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 94 c1 0f 95 c2 83 f8 0a 0f 9c c5 83 f8 09 b8 ?? ?? ?? ?? 0f 9f c6 20 d5 20 f1 08 d6 08 cd 88 e9 30 f1 84 ed 0f 45 c6 84 f6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}