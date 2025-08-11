
rule Trojan_Win64_Dllhijack_CCJW_MTB{
	meta:
		description = "Trojan:Win64/Dllhijack.CCJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c6 8b ce c1 e0 06 c1 e9 08 33 c8 8b c7 83 e0 03 41 03 4c 85 00 03 ce 03 cf 43 29 4c 26 04 43 8b 44 26 04 43 89 04 26 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}