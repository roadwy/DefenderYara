
rule Trojan_Win64_FileCoder_ARAZ_MTB{
	meta:
		description = "Trojan:Win64/FileCoder.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c8 89 c1 48 8d 55 a0 48 8b 85 c8 04 00 00 48 01 d0 88 08 48 83 85 c8 04 00 00 01 48 8b 85 c8 04 00 00 48 3b 85 a8 04 00 00 72 a1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}