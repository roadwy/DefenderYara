
rule Trojan_Win32_Formbook_MA_MTB{
	meta:
		description = "Trojan:Win32/Formbook.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c8 85 c9 74 1c 8b c7 2b c8 bb 05 1a 00 00 8b ff 8a 04 0f 88 07 8d 7f 01 4b 75 } //5
		$a_01_1 = {57 00 49 00 4f 00 53 00 4f 00 53 00 4f 00 53 00 4f 00 57 00 } //5 WIOSOSOSOW
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}
rule Trojan_Win32_Formbook_MA_MTB_2{
	meta:
		description = "Trojan:Win32/Formbook.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_80_0 = {43 6f 76 65 72 57 61 74 65 72 61 67 65 36 34 } //CoverWaterage64  1
		$a_80_1 = {52 65 6d 65 6d 62 65 72 46 6c 69 6e 63 68 33 32 } //RememberFlinch32  1
		$a_80_2 = {54 6f 45 6c 65 63 74 72 6f 65 6e 63 65 70 68 61 6c 6f 67 72 61 70 68 79 } //ToElectroencephalography  1
		$a_80_3 = {52 65 6d 65 6d 62 65 72 53 68 69 70 77 72 69 67 68 74 } //RememberShipwright  1
		$a_80_4 = {53 70 65 61 6b 43 61 74 61 6d 6f 75 6e 74 61 69 6e } //SpeakCatamountain  1
		$a_80_5 = {4e 65 77 73 70 61 70 65 72 77 6f 6d 61 6e } //Newspaperwoman  1
		$a_80_6 = {5f 43 75 74 43 6f 62 62 6c 65 33 32 2e 64 6c 6c } //_CutCobble32.dll  1
		$a_80_7 = {53 75 6e 68 61 74 73 } //Sunhats  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=7
 
}
rule Trojan_Win32_Formbook_MA_MTB_3{
	meta:
		description = "Trojan:Win32/Formbook.MA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 c3 de 41 00 00 b9 de 89 00 00 48 40 81 c1 2a b0 00 00 81 e1 51 57 00 00 c2 e3 ba f7 d2 81 f2 34 12 01 00 4a 2d ad 38 00 00 4b 42 5b 81 c2 bc 5b 01 00 3d c9 55 00 00 74 0d } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}