
rule Trojan_Win64_Rootkit_LR_MTB{
	meta:
		description = "Trojan:Win64/Rootkit.LR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 0b 48 8b 43 08 44 89 3c 88 ff 03 41 ff c6 44 3b b5 80 00 00 00 } //20
		$a_01_1 = {41 56 41 57 48 8d 6c 24 c0 48 81 ec 40 01 00 00 48 83 64 24 58 00 48 8d 85 80 00 00 00 48 83 64 24 50 00 4c 8b e2 48 83 64 24 48 00 48 8b d9 48 83 64 24 40 00 45 33 c9 48 89 44 24 38 45 33 c0 48 83 64 24 30 00 33 d2 48 83 64 24 28 00 49 8b cc } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}