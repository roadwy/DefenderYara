
rule Trojan_Win32_Lazy_LML_MTB{
	meta:
		description = "Trojan:Win32/Lazy.LML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 89 04 6e b9 4b 00 00 00 66 89 4c 24 28 ba 45 00 00 00 66 89 54 24 2a b8 52 00 00 00 66 89 44 24 2c 66 89 54 24 30 b9 4e 00 00 00 66 89 4c 24 2e b8 4c 00 00 00 66 89 44 24 32 ba 32 00 00 00 66 89 54 24 36 b9 33 00 00 00 66 89 4c 24 34 ba 4c 00 00 00 b8 2e 00 00 00 66 89 44 24 38 8b c2 b9 44 00 00 00 66 89 54 24 3c 66 89 4c 24 3a b2 72 } //20
		$a_81_1 = {4d 69 63 72 6f 73 30 66 74 45 64 67 65 55 70 64 61 74 65 54 61 73 6b 30 55 41 20 54 61 73 6b 2d 53 2d 31 2d 35 2d 31 38 } //10 Micros0ftEdgeUpdateTask0UA Task-S-1-5-18
	condition:
		((#a_01_0  & 1)*20+(#a_81_1  & 1)*10) >=30
 
}