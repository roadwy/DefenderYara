
rule Trojan_Win64_ClipBanker_C_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 81 ec 70 02 00 00 48 8d 6c 24 20 48 8d 0d 41 95 13 00 e8 0b ba ff ff ba 20 00 00 00 48 8d 0d 68 78 12 00 e8 e0 88 ff ff 48 8d 15 d4 18 0f 00 48 8d 8d 50 01 00 00 e8 9b 9c ff ff 90 } //2
		$a_01_1 = {5c 43 6c 69 70 65 7a 5c 78 36 34 5c 44 65 62 75 67 5c 43 6c 69 70 65 7a 2e 70 64 62 } //2 \Clipez\x64\Debug\Clipez.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}