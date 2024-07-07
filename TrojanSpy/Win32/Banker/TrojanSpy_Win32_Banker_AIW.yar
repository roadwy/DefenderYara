
rule TrojanSpy_Win32_Banker_AIW{
	meta:
		description = "TrojanSpy:Win32/Banker.AIW,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 76 20 46 6f 72 63 65 41 75 74 6f 4c 6f 67 6f 6e 20 2f 64 20 31 20 2f 74 20 52 45 47 5f 53 5a 20 2f 66 } //1 /v ForceAutoLogon /d 1 /t REG_SZ /f
		$a_01_1 = {2d 43 20 2d 73 73 68 20 2d 32 20 2d 50 20 32 32 20 2d 69 20 } //1 -C -ssh -2 -P 22 -i 
		$a_01_2 = {45 72 61 73 65 20 22 25 73 22 } //1 Erase "%s"
		$a_01_3 = {43 61 64 61 73 74 72 61 64 6f } //1 Cadastrado
		$a_01_4 = {6c 69 6e 6b 65 6d 61 69 6c 3d } //1 linkemail=
		$a_01_5 = {73 65 6e 68 61 3d } //1 senha=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}