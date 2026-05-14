
rule Trojan_Win64_DustyHammock_GVA_MTB{
	meta:
		description = "Trojan:Win64/DustyHammock.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {a8 01 0f 85 08 01 00 00 49 ff c4 30 da 42 88 14 2e 49 ff c5 4d 89 f8 eb bb 0f 10 45 f0 48 8d 55 b0 0f 29 02 4c 89 6a 10 48 8d bd 18 01 00 00 48 89 f9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}