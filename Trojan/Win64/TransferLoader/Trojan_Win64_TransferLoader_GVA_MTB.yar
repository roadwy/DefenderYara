
rule Trojan_Win64_TransferLoader_GVA_MTB{
	meta:
		description = "Trojan:Win64/TransferLoader.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 0f af d3 4c 8b c2 4d 0f af c3 4a 8d 04 0a 4d 8b cb 48 03 c1 48 8b c8 48 c1 e0 20 48 c1 e9 20 48 0b c8 0f b7 c1 66 33 43 02 66 89 47 02 4a 8d 04 11 } //2
		$a_01_1 = {41 8d 0c 00 69 d1 29 27 2e bf 45 8d 52 01 c1 ca 11 81 c2 29 27 2e bf 03 c2 c1 c8 0f 41 0f af c0 47 0f be 04 0a 03 c0 8b d0 c1 c8 0e c1 ca 10 45 85 c0 75 cc } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}