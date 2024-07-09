
rule TrojanSpy_Win32_Banker_ACC{
	meta:
		description = "TrojanSpy:Win32/Banker.ACC,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {6f 72 64 65 72 20 62 79 20 4e 4d 5f 49 44 20 64 65 73 63 } //1 order by NM_ID desc
		$a_02_1 = {48 6f 73 74 3d 73 6d 74 70 [0-01] 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 } //1
		$a_00_2 = {6c 6f 67 69 6e 62 6f 74 6f 65 73 3a 62 6f 74 61 6f 41 76 61 6e 63 61 72 } //1 loginbotoes:botaoAvancar
		$a_00_3 = {2f 69 62 70 66 6c 6f 67 69 6e 2f 69 64 65 6e 74 69 66 69 63 61 63 61 6f 2e 6a 73 66 } //1 /ibpflogin/identificacao.jsf
		$a_00_4 = {6f 6e 43 6c 69 63 6b 3d 22 65 6e 76 69 61 54 75 64 6f 28 29 3b 22 20 } //1 onClick="enviaTudo();" 
		$a_00_5 = {53 2d 45 2d 52 2d 41 2d 53 2d 41 } //1 S-E-R-A-S-A
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}