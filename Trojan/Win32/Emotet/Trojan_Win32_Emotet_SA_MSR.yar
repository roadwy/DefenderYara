
rule Trojan_Win32_Emotet_SA_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 55 73 65 72 73 5c 55 73 65 72 5c 44 65 73 6b 74 6f 70 5c 32 30 30 33 5c 63 61 6c 63 64 72 69 76 5c 52 65 6c 65 61 73 65 5c 63 61 6c 63 64 72 69 76 2e 70 64 62 } //1 c:\Users\User\Desktop\2003\calcdriv\Release\calcdriv.pdb
		$a_01_1 = {63 61 6c 63 64 72 69 76 2e 65 78 65 } //1 calcdriv.exe
		$a_01_2 = {53 6c 65 65 70 } //1 Sleep
		$a_01_3 = {6d 00 66 00 63 00 63 00 61 00 6c 00 63 00 2e 00 63 00 61 00 6c 00 63 00 75 00 6c 00 61 00 74 00 6f 00 72 00 } //1 mfccalc.calculator
		$a_01_4 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 } //1 Application Data
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Emotet_SA_MSR_2{
	meta:
		description = "Trojan:Win32/Emotet.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {41 66 78 43 6f 6e 74 72 6f 6c 42 61 72 ?? ?? 73 } //1
		$a_03_1 = {41 66 78 4d 44 49 46 72 61 6d 65 ?? ?? 73 } //1
		$a_03_2 = {41 66 78 46 72 61 6d 65 4f 72 56 69 65 77 ?? ?? 73 } //1
		$a_01_3 = {4d 00 46 00 43 00 20 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //1 MFC Application
		$a_01_4 = {43 00 52 00 59 00 50 00 54 00 33 00 32 00 2e 00 44 00 4c 00 4c 00 } //1 CRYPT32.DLL
		$a_01_5 = {43 00 72 00 79 00 70 00 74 00 53 00 74 00 72 00 69 00 6e 00 67 00 54 00 6f 00 42 00 69 00 6e 00 61 00 72 00 79 00 41 00 } //1 CryptStringToBinaryA
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}