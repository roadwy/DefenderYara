
rule Trojan_Win64_Kazuar_C_dha{
	meta:
		description = "Trojan:Win64/Kazuar.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 31 c0 44 8b 54 24 38 49 89 cb 41 8d 48 01 48 89 d7 48 01 c9 89 c9 f3 aa 31 c0 41 8a 0c 03 45 0f af d1 44 03 54 24 30 44 31 d1 0f b6 c9 66 89 0c 42 48 ff c0 41 39 c0 77 e1 5f c3 } //10
		$a_01_1 = {57 31 c0 44 8b 54 24 38 49 89 cb 48 89 d7 41 8d 48 01 f3 aa 31 c0 41 8a 0c 03 45 0f af d1 44 03 54 24 30 44 31 d1 88 0c 02 48 ff c0 41 39 c0 77 e5 5f c3 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}