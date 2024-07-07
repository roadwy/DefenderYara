
rule Trojan_Win64_ClipBanker_PAAY_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.PAAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 bb 32 c9 bf 4b 49 c1 cb 14 49 f7 d3 8b 4f fc 33 cb 41 8b c3 45 8b c3 c1 c1 02 4f 8d 94 d8 2c 75 30 f8 4c 8d 0c 45 3e 95 2c a9 0f c9 4a 8d 14 95 82 3a 14 9a 49 c1 f0 53 41 50 f7 d9 81 e9 18 a4 35 8f 48 c1 24 24 f6 48 c1 f0 6a 48 01 1c 24 41 81 ca 1c e7 08 b0 f6 da 49 0f c1 c3 31 0c 24 4d 2b ca 5b 49 f7 da 41 f6 db } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}