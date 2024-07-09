
rule Trojan_Win64_r77RootKit_A_MTB{
	meta:
		description = "Trojan:Win64/r77RootKit.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 10 00 0f 10 48 10 48 8d 80 ?? ?? ?? ?? 0f 11 42 80 0f 10 40 a0 0f 11 4a ?? 0f 10 48 b0 0f 11 42 a0 0f 10 40 c0 0f 11 4a b0 0f 10 48 d0 0f 11 42 c0 0f 10 40 e0 0f 11 4a d0 0f 10 48 f0 0f 11 42 e0 0f 11 4a f0 48 83 e9 } //2
		$a_01_1 = {52 37 37 2e 70 64 62 } //2 R77.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}