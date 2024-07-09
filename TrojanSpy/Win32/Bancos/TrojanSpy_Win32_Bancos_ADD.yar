
rule TrojanSpy_Win32_Bancos_ADD{
	meta:
		description = "TrojanSpy:Win32/Bancos.ADD,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {2d 63 6f 6e 74 61 74 6f 73 2e 74 78 74 } //1 -contatos.txt
		$a_01_1 = {6e 61 6d 65 3d 63 68 6b 5f 65 6d 61 69 6c 5b 5d } //1 name=chk_email[]
		$a_01_2 = {45 6e 74 72 61 72 20 2d 00 } //1
		$a_01_3 = {53 69 67 6e 20 49 6e 20 2d 00 } //1
		$a_01_4 = {74 65 6c 6e 65 74 3a 2f 2f } //1 telnet://
		$a_03_5 = {6e 76 70 5f 62 75 5f 73 65 6e 64 00 [0-40] 72 65 64 69 72 5f 67 6d 61 69 6c 00 } //1
		$a_01_6 = {5c 49 6e 74 65 72 6e 65 74 20 53 65 74 74 69 6e 67 73 5c 55 73 65 72 20 41 67 65 6e 74 5c 50 6f 73 74 20 50 6c 61 74 66 6f 72 6d } //1 \Internet Settings\User Agent\Post Platform
		$a_01_7 = {6c 6f 67 69 6e 3f 6c 6f 67 6f 75 74 3d 31 26 2e 69 6e 74 6c 3d 62 72 26 2e 73 72 63 3d 79 6d 26 2e 70 64 3d 79 6d 5f 76 65 72 } //1 login?logout=1&.intl=br&.src=ym&.pd=ym_ver
		$a_03_8 = {2f 00 6d 00 61 00 69 00 6c 00 2f 00 68 00 2f 00 [0-10] 2f 00 3f 00 76 00 3d 00 62 00 26 00 70 00 76 00 3d 00 74 00 6c 00 26 00 63 00 73 00 3d 00 62 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*1) >=5
 
}