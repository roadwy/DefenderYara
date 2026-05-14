
rule Trojan_Win32_Shodi_AMTB{
	meta:
		description = "Trojan:Win32/Shodi!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {55 73 61 53 68 6f 68 64 69 } //UsaShohdi  1
		$a_80_1 = {63 63 52 65 67 56 66 79 2e 65 78 65 } //ccRegVfy.exe  1
		$a_80_2 = {63 63 41 70 70 2e 65 78 65 } //ccApp.exe  1
		$a_80_3 = {5c 2a 2e 65 78 65 } //\*.exe  1
		$a_80_4 = {46 75 63 6b 20 79 6f 75 20 70 72 65 73 69 64 65 6e 74 20 6f 66 20 55 53 41 20 2c 20 46 75 63 6b 20 79 6f 75 20 20 22 62 75 73 68 20 74 68 65 20 73 6f 6e 22 } //Fuck you president of USA , Fuck you  "bush the son"  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}