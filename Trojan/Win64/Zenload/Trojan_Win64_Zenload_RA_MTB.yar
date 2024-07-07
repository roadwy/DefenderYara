
rule Trojan_Win64_Zenload_RA_MTB{
	meta:
		description = "Trojan:Win64/Zenload.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 cc c0 e9 04 80 e1 03 0f b6 84 24 a8 00 00 00 c0 e0 02 02 c8 88 8c 24 a0 00 00 00 0f b6 84 24 aa 00 00 00 c0 e8 02 24 0f 41 c0 e4 04 41 32 c4 88 84 24 a1 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}