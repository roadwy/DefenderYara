
rule Trojan_Win64_Bumblebee_TRR_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.TRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b cf 44 89 54 24 30 89 44 24 28 8b 44 24 70 89 44 24 20 e8 b9 cd ff ff 8b 4f 28 41 83 c4 04 2b 8f f8 02 00 00 44 8b e8 48 8b 97 58 01 00 00 41 2b ce 44 8b 8c 24 ?? ?? ?? ?? 44 33 f9 44 8b 44 24 68 48 2b d3 44 8b 94 24 30 01 00 00 44 8b 9c 24 20 01 00 00 49 63 cc 48 3b ca 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}