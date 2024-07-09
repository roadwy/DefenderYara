
rule Trojan_Win32_Dridex_OD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.OD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 08 05 [0-04] 8b [0-03] 83 [0-02] 89 [0-03] 89 [0-03] 8b [0-03] 35 [0-04] 8b [0-03] 8b [0-03] 81 [0-05] 8b [0-03] 83 [0-02] 89 [0-03] 89 [0-03] 01 ?? 89 [0-03] 8a [0-03] 88 [0-03] eb } //7
		$a_81_1 = {42 74 68 65 6d 61 64 64 72 65 73 73 } //1 Bthemaddress
		$a_81_2 = {62 61 73 69 63 74 68 65 6d 65 73 47 6f 6f 67 6c 65 } //1 basicthemesGoogle
		$a_81_3 = {46 45 64 6f 77 6e 6c 6f 61 64 69 6e 67 45 64 75 65 } //1 FEdownloadingEdue
		$a_81_4 = {38 66 6f 75 72 2d 70 61 72 74 38 43 68 72 6f 6d 65 2c 5a 53 4d 74 68 65 69 72 58 } //1 8four-part8Chrome,ZSMtheirX
		$a_81_5 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //1 OutputDebugStringA
		$a_81_6 = {43 68 72 6f 6d 65 73 74 72 69 6e 67 2c 6b 61 72 65 33 } //1 Chromestring,kare3
		$a_81_7 = {41 76 69 72 61 20 47 6d 62 48 } //1 Avira GmbH
	condition:
		((#a_02_0  & 1)*7+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=7
 
}