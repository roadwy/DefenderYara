
rule TrojanSpy_Win32_Bancos_AHG{
	meta:
		description = "TrojanSpy:Win32/Bancos.AHG,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
		$a_03_1 = {43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e 00 [0-10] 45 6e 61 62 6c 65 4c 55 41 00 } //1
		$a_00_2 = {8b 37 85 db 74 15 8a 02 3c 61 72 06 3c 7a 77 02 2c 20 88 06 42 46 4b } //1
		$a_01_3 = {54 65 72 6d 69 6e 6f 75 20 64 6f 77 6e 6c 6f 61 64 } //1 Terminou download
		$a_01_4 = {2f 63 61 64 5f 76 65 72 73 61 6f 5f 69 65 2e 70 68 70 3f 76 65 72 73 61 6f 3d } //1 /cad_versao_ie.php?versao=
		$a_02_5 = {03 c7 b9 ff 00 00 00 99 f7 f9 8b da 3b 75 f0 7d ?? 46 eb ?? be 01 00 00 00 8b 45 e8 0f b6 44 30 ff 33 d8 8d 45 cc 50 89 5d d0 c6 45 d4 00 8d 55 d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_02_5  & 1)*1) >=5
 
}