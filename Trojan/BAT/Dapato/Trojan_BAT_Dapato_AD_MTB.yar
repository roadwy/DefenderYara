
rule Trojan_BAT_Dapato_AD_MTB{
	meta:
		description = "Trojan:BAT/Dapato.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 2c 13 07 2c 04 16 0b 2b 0c 72 f5 02 00 70 28 ?? ?? ?? 0a 16 2a 09 17 58 0d 09 08 8e 69 32 d3 72 1d 03 00 70 } //2
		$a_01_1 = {43 00 61 00 6c 00 6c 00 43 00 6f 00 72 00 65 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 CallCoreInstall.exe
		$a_01_2 = {61 00 6c 00 73 00 6f 00 70 00 77 00 6e 00 72 00 75 00 6e 00 } //1 alsopwnrun
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule Trojan_BAT_Dapato_AD_MTB_2{
	meta:
		description = "Trojan:BAT/Dapato.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 11 04 2c 16 00 06 28 ?? 00 00 0a 00 72 ?? 00 00 70 28 ?? 00 00 0a 00 00 2b 0d 00 72 ?? 00 00 70 28 ?? 00 00 0a 00 00 00 de 05 } //2
		$a_01_1 = {73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 41 6e 79 44 65 73 6b 41 64 64 2e 65 78 65 5c 41 6e 79 44 65 73 6b 41 64 64 2e 65 78 65 5c 6f 62 6a 5c 44 65 62 75 67 5c 41 6e 79 44 65 73 6b 41 64 64 2e 65 78 65 2e 70 64 62 } //1 source\repos\AnyDeskAdd.exe\AnyDeskAdd.exe\obj\Debug\AnyDeskAdd.exe.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}