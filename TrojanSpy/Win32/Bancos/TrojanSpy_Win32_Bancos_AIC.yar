
rule TrojanSpy_Win32_Bancos_AIC{
	meta:
		description = "TrojanSpy:Win32/Bancos.AIC,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {69 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 65 00 78 00 65 00 [0-08] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 [0-08] 4b 00 45 00 59 00 } //10
		$a_00_1 = {70 00 61 00 6e 00 6b 00 64 00 5f 00 6c 00 6f 00 61 00 64 00 5f 00 76 00 62 00 5c 00 76 00 65 00 6a 00 74 00 75 00 64 00 6f 00 2e 00 76 00 62 00 70 00 } //1 pankd_load_vb\vejtudo.vbp
		$a_00_2 = {47 00 45 00 52 00 41 00 44 00 4f 00 52 00 5f 00 41 00 56 00 5f 00 4b 00 49 00 4c 00 4c 00 5f 00 65 00 6d 00 20 00 65 00 78 00 65 00 5c 00 76 00 65 00 74 00 69 00 6d 00 5f 00 6c 00 6f 00 61 00 64 00 5f 00 76 00 62 00 } //1 GERADOR_AV_KILL_em exe\vetim_load_vb
		$a_03_3 = {77 00 69 00 6e 00 64 00 69 00 72 00 [0-0a] 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 6a 00 72 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=11
 
}