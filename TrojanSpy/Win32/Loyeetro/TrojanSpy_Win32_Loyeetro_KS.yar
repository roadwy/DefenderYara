
rule TrojanSpy_Win32_Loyeetro_KS{
	meta:
		description = "TrojanSpy:Win32/Loyeetro.KS,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 68 75 74 75 70 5f 41 6e 64 5f 46 75 63 6b 6f 66 2e 64 6c 6c } //1 Shutup_And_Fuckof.dll
		$a_00_1 = {5c 55 73 65 72 73 5c 52 61 7a 5c 44 65 73 6b 74 6f 70 5c 53 74 75 64 65 6e 74 50 72 6f 6a 65 63 74 5c 53 68 75 74 75 70 5f 41 6e 64 5f 46 75 63 6b 6f 66 5c 6f 62 6a 5c 44 65 62 75 67 5c 53 68 75 74 75 70 5f 41 6e 64 5f 46 75 63 6b 6f 66 2e 70 64 62 } //2 \Users\Raz\Desktop\StudentProject\Shutup_And_Fuckof\obj\Debug\Shutup_And_Fuckof.pdb
		$a_01_2 = {49 5f 44 4b 5f 57 48 41 54 5f 55 5f 44 4f 49 4e 47 5f 48 45 52 45 5f 46 55 43 4b 4f 46 46 } //1 I_DK_WHAT_U_DOING_HERE_FUCKOFF
		$a_00_3 = {53 74 75 64 65 6e 74 50 72 6f 6a 65 63 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 StudentProject.Properties.Resources.resources
		$a_01_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*2+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}