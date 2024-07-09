
rule TrojanDownloader_BAT_Remcos_SPL_MTB{
	meta:
		description = "TrojanDownloader:BAT/Remcos.SPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 18 2d 05 26 16 0d 2b 03 0c 2b f9 08 12 03 28 ?? ?? ?? 0a 06 03 07 28 ?? ?? ?? 06 6f ?? ?? ?? 0a de 0a 09 2c 06 08 28 ?? ?? ?? 0a dc 07 18 58 0b 07 03 6f ?? ?? ?? 0a 32 c6 } //5
		$a_81_1 = {4f 74 68 75 62 70 6d 2e 65 78 65 } //3 Othubpm.exe
		$a_01_2 = {2f 00 32 00 30 00 37 00 2e 00 31 00 36 00 37 00 2e 00 36 00 34 00 2e 00 31 00 32 00 32 00 2f 00 46 00 76 00 6b 00 70 00 6b 00 70 00 77 00 2e 00 62 00 6d 00 70 00 } //3 /207.167.64.122/Fvkpkpw.bmp
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*3+(#a_01_2  & 1)*3) >=11
 
}