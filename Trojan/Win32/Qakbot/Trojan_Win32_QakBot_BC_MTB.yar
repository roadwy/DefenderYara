
rule Trojan_Win32_QakBot_BC_MTB{
	meta:
		description = "Trojan:Win32/QakBot.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 63 35 68 69 76 42 67 } //3 Cc5hivBg
		$a_01_1 = {43 6d 71 38 56 77 43 52 46 } //3 Cmq8VwCRF
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //3 DllRegisterServer
		$a_01_3 = {44 75 4e 68 4d 39 30 36 } //3 DuNhM906
		$a_01_4 = {44 78 4d 30 49 6f 65 } //3 DxM0Ioe
		$a_01_5 = {53 63 72 69 70 74 53 74 72 69 6e 67 58 74 6f 43 50 } //3 ScriptStringXtoCP
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=18
 
}
rule Trojan_Win32_QakBot_BC_MTB_2{
	meta:
		description = "Trojan:Win32/QakBot.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 00 e8 90 02 04 2b d8 a1 90 02 04 33 18 89 1d 90 02 04 6a 00 e8 90 02 04 8b d8 03 1d 90 02 04 6a 00 e8 90 02 04 03 d8 6a 00 e8 90 02 04 03 d8 6a 00 e8 90 02 04 03 d8 6a 00 e8 90 02 04 03 d8 a1 90 02 04 89 18 6a 00 e8 90 02 04 8b d8 a1 90 02 04 83 c0 04 03 d8 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_QakBot_BC_MTB_3{
	meta:
		description = "Trojan:Win32/QakBot.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af da 8b d3 c1 ea 08 88 14 01 ff 47 68 8b 4f 68 8b 87 b4 00 00 00 88 1c 01 8b 47 78 ff 47 68 35 40 77 20 00 29 47 6c 8b 87 c0 00 00 00 2b 47 6c 2d 90 02 04 31 47 78 8b 47 74 2d 90 02 04 01 47 64 8b 47 64 83 c0 ed 01 87 80 00 00 00 81 fd 90 02 04 0f 90 00 } //4
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}