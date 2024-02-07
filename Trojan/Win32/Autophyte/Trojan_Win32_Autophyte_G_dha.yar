
rule Trojan_Win32_Autophyte_G_dha{
	meta:
		description = "Trojan:Win32/Autophyte.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0d 00 00 05 00 "
		
	strings :
		$a_02_0 = {8a 01 3c 69 7c 90 01 01 3c 70 7f 90 01 01 04 09 eb 90 01 01 3c 72 7c 90 01 01 3c 79 7e 90 01 01 3c 49 7c 90 01 01 3c 50 90 02 06 3c 52 7c 90 01 01 3c 59 7f 90 01 01 2c 09 90 00 } //01 00 
		$a_01_1 = {2d 2d 2d 2d 46 78 69 76 42 78 6c 77 64 61 69 70 } //01 00  ----FxivBxlwdaip
		$a_01_2 = {41 63 63 65 79 6b 3a } //01 00  Acceyk:
		$a_01_3 = {4e 4a 41 4a 6b 61 69 6b 6c 79 } //01 00  NJAJkaikly
		$a_01_4 = {6a 78 63 74 65 6b } //01 00  jxctek
		$a_01_5 = {47 65 6b 4b 65 76 79 59 61 6b 68 } //01 00  GekKevyYakh
		$a_01_6 = {49 65 61 64 46 72 75 65 } //01 00  IeadFrue
		$a_01_7 = {49 65 67 51 6c 65 69 70 4d 61 75 6c 65 } //01 00  IegQleipMaule
		$a_01_8 = {59 69 78 63 65 6a 6a 33 32 57 65 6f 6b } //01 00  Yixcejj32Weok
		$a_01_9 = {5f 5f 57 53 41 46 44 49 6a 53 65 6b } //01 00  __WSAFDIjSek
		$a_01_10 = {57 53 41 43 75 65 61 77 6c 79 } //01 00  WSACueawly
		$a_01_11 = {57 53 41 53 6b 61 69 6b 6c 79 } //01 00  WSASkaikly
		$a_01_12 = {52 65 61 64 46 72 75 65 } //00 00  ReadFrue
	condition:
		any of ($a_*)
 
}