
rule Trojan_Win32_Jinnir_A{
	meta:
		description = "Trojan:Win32/Jinnir.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6a 02 6a 00 6a fc 56 ff d5 8d 54 24 14 8d 44 24 10 6a 00 52 6a 04 50 56 } //2
		$a_01_1 = {40 00 8b 44 24 10 b9 fc ff ff ff 6a 02 2b c8 6a 00 51 56 ff d5 8d 54 24 14 8b 44 24 10 6a 00 52 50 53 56 } //3
		$a_03_2 = {8b 08 8d 55 e0 52 50 ff 51 34 8b 45 e0 3b c3 74 07 8b 00 3b 45 c4 74 90 01 01 8b 45 e4 8b 08 90 00 } //2
		$a_01_3 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5f 53 65 72 76 65 72 } //1 Internet Explorer_Server
		$a_01_4 = {57 4d 5f 48 54 4d 4c 5f 47 45 54 4f 42 4a 45 43 54 } //1 WM_HTML_GETOBJECT
		$a_01_5 = {3c 49 46 52 41 4d 45 20 61 6c 69 67 6e 3d 63 65 6e 74 65 72 } //1 <IFRAME align=center
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}