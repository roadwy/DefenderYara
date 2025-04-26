
rule Trojan_Win32_RisePro_EM_MTB{
	meta:
		description = "Trojan:Win32/RisePro.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {46 5c 31 44 32 33 45 38 30 31 46 46 39 31 36 46 31 43 2d 44 46 36 39 43 45 33 34 38 34 41 45 34 31 42 42 31 } //1 F\1D23E801FF916F1C-DF69CE3484AE41BB1
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 45 6e 69 67 6d 61 20 50 72 6f 74 65 63 74 6f 72 5c 42 42 33 44 46 31 46 44 42 42 39 33 35 45 39 42 2d 35 30 41 46 41 36 45 32 37 46 38 41 33 32 41 46 } //1 Software\Enigma Protector\BB3DF1FDBB935E9B-50AFA6E27F8A32AF
		$a_81_2 = {65 6e 69 67 6d 61 5f 69 64 65 2e 64 6c 6c } //1 enigma_ide.dll
		$a_81_3 = {63 3a 5c 64 65 62 75 67 2e 6c 6f 67 } //1 c:\debug.log
		$a_81_4 = {44 4c 4c 5f 4c 6f 61 64 65 72 2e 64 6c 6c } //1 DLL_Loader.dll
		$a_81_5 = {45 50 5f 43 68 65 63 6b 55 70 53 74 61 72 74 75 70 50 61 73 73 77 6f 72 64 48 61 73 68 53 74 72 69 6e 67 } //1 EP_CheckUpStartupPasswordHashString
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}