
rule Trojan_Win32_LummaC_NLF_MTB{
	meta:
		description = "Trojan:Win32/LummaC.NLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b7 c9 89 cb f7 d3 0f b7 f6 21 f3 01 db 31 f1 31 c0 39 cb 0f 94 c0 8b 4c 24 04 } //2
		$a_01_1 = {0f be 0c 1e 31 d1 0f af cd 43 89 ca 39 df 75 f0 } //1
		$a_01_2 = {90 89 ca 80 c2 06 32 54 0c 1c 80 c2 d0 88 54 0c 1c 41 83 f9 04 75 ea } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}