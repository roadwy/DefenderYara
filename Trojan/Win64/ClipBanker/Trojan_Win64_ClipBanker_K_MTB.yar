
rule Trojan_Win64_ClipBanker_K_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f be 00 88 41 78 8b d0 48 8d 0d 7b 04 03 00 e8 f2 99 00 00 0f be 4b 78 48 85 c0 8b c1 75 } //2
		$a_01_1 = {5c 73 74 75 62 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 73 74 75 62 2e 70 64 62 } //2 \stub\x64\Release\stub.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}