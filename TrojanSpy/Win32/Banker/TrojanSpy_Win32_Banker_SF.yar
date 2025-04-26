
rule TrojanSpy_Win32_Banker_SF{
	meta:
		description = "TrojanSpy:Win32/Banker.SF,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {45 34 30 36 33 37 45 38 30 45 33 38 32 30 43 36 36 32 38 41 42 33 41 41 35 43 38 37 42 35 36 37 39 38 35 41 } //4 E40637E80E3820C6628AB3AA5C87B567985A
		$a_80_1 = {20 28 4e 5f 50 43 20 2c 20 4e 5f 4e 4f 4d 45 20 2c 20 44 54 5f 44 41 54 41 20 2c 20 54 58 54 5f 43 54 29 20 56 41 4c 55 45 53 20 28 3a 50 43 20 2c 20 3a 4e 4f 4d 45 20 2c 20 3a 44 41 54 41 20 2c 20 3a 43 54 29 20 } // (N_PC , N_NOME , DT_DATA , TXT_CT) VALUES (:PC , :NOME , :DATA , :CT)   4
		$a_01_2 = {74 6d 5f 67 65 62 62 30 31 54 69 6d 65 72 } //2 tm_gebb01Timer
	condition:
		((#a_01_0  & 1)*4+(#a_80_1  & 1)*4+(#a_01_2  & 1)*2) >=10
 
}