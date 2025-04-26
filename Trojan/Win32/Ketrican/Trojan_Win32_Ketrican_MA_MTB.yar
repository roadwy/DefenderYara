
rule Trojan_Win32_Ketrican_MA_MTB{
	meta:
		description = "Trojan:Win32/Ketrican.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c6 8b 4d e8 8a 14 08 88 54 1d f8 43 41 89 5d ec 89 4d e8 83 fb 04 75 6d 33 f6 8a 44 35 f8 6a 01 8d 4d fc 51 88 45 fc } //5
		$a_01_1 = {6c 6f 63 61 6c 68 6f 73 74 26 63 6c 69 65 6e 74 5f 73 65 63 72 65 74 3d } //1 localhost&client_secret=
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}