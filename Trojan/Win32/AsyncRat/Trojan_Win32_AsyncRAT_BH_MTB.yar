
rule Trojan_Win32_AsyncRAT_BH_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f6 a4 c5 4e 52 b2 70 44 88 a8 80 05 1e 78 66 cc 80 74 83 d9 f9 cc 34 93 25 a2 04 74 b8 5a b5 46 33 8d a9 21 a8 be 02 ce a6 e0 } //01 00 
		$a_01_1 = {c0 b4 4c 8b dd 22 87 f8 f7 ae 3d 1f 12 e5 10 10 30 01 67 a1 e8 87 9f c4 17 3d 4e 81 bd 82 42 1e e1 } //00 00 
	condition:
		any of ($a_*)
 
}