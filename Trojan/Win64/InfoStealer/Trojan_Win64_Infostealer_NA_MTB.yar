
rule Trojan_Win64_Infostealer_NA_MTB{
	meta:
		description = "Trojan:Win64/Infostealer.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 4d 75 73 71 75 69 74 61 6f 5c 44 65 73 6b 74 6f 70 5c 42 52 5f 32 30 32 33 5c 4c 4f 41 44 43 50 50 32 30 32 34 5c 4c 4f 41 44 5f 45 58 45 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 4c 4f 41 44 5f 45 58 45 2e 70 64 62 } //2 C:\Users\Musquitao\Desktop\BR_2023\LOADCPP2024\LOAD_EXE\x64\Release\LOAD_EXE.pdb
		$a_81_1 = {4d 75 73 71 75 69 74 61 6f } //1 Musquitao
		$a_81_2 = {73 65 74 74 69 6e 67 73 2e 64 61 74 } //1 settings.dat
		$a_81_3 = {73 65 63 78 65 74 65 20 31 } //1 secxete 1
		$a_81_4 = {41 6e 61 70 6f 6c 6f 73 20 32 } //1 Anapolos 2
		$a_81_5 = {68 74 7a 70 3a 2f 2f } //1 htzp://
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}