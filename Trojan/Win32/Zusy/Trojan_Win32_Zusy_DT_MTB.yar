
rule Trojan_Win32_Zusy_DT_MTB{
	meta:
		description = "Trojan:Win32/Zusy.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 ef 17 8d 44 38 0d 88 44 24 0d 30 59 0d 83 fa 0e 74 } //01 00 
		$a_01_1 = {0f b7 54 08 0a 8a 5c 08 1a c1 e2 10 80 f3 ea 74 } //01 00 
		$a_01_2 = {44 64 71 44 70 74 64 6d 67 6c 77 4d 67 72 71 6f 61 72 44 70 6f 6f 41 6b 64 52 } //01 00  DdqDptdmglwMgrqoarDpooAkdR
		$a_01_3 = {4a 72 55 73 67 67 6d 77 77 6a 71 4e 6c 67 77 73 76 64 52 70 65 71 65 66 7c } //01 00  JrUsggmwwjqNlgwsvdRpeqef|
		$a_01_4 = {51 75 69 44 79 71 69 68 51 6b 6a 6b 66 62 66 55 70 73 6b 6c 67 } //00 00  QuiDyqihQkjkfbfUpsklg
	condition:
		any of ($a_*)
 
}