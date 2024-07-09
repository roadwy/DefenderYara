
rule TrojanSpy_Win32_Bancos_DD{
	meta:
		description = "TrojanSpy:Win32/Bancos.DD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 75 74 6f 20 45 6e 76 69 6f 20 4d 73 6e } //1 Auto Envio Msn
		$a_03_1 = {50 72 6f 76 69 64 65 72 3d 53 51 4c 4f 4c 45 44 42 2e 31 3b 50 61 73 73 77 6f 72 64 3d [0-10] 3b 50 65 72 73 69 73 74 20 53 65 63 75 72 69 74 79 20 49 6e 66 6f 3d 54 72 75 65 3b 55 73 65 72 20 49 44 3d [0-10] 3b 49 6e 69 74 69 61 6c 20 43 61 74 61 6c 6f 67 3d [0-10] 3b 44 61 74 61 20 53 6f 75 72 63 65 3d 32 30 31 2e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}