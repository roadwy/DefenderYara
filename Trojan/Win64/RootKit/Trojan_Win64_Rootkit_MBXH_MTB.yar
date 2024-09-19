
rule Trojan_Win64_Rootkit_MBXH_MTB{
	meta:
		description = "Trojan:Win64/Rootkit.MBXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 85 94 4a 02 00 41 89 49 08 49 f7 c1 06 61 e3 46 45 89 51 04 44 3a dc 41 80 f8 09 e9 23 34 17 00 c1 63 6b 6f 1d 89 b1 df 27 c5 4b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}