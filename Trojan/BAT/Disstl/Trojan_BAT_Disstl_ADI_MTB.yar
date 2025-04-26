
rule Trojan_BAT_Disstl_ADI_MTB{
	meta:
		description = "Trojan:BAT/Disstl.ADI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {a2 25 17 28 ?? ?? ?? 0a a2 25 18 72 50 01 00 70 a2 25 19 02 7b 05 00 00 04 a2 25 1a 72 54 01 00 70 a2 28 ?? ?? ?? 0a 0c 07 06 } //2
		$a_01_1 = {5c 64 65 62 75 67 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 50 63 43 6c 65 61 6e 65 72 5c 50 63 43 6c 65 61 6e 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c 50 63 43 6c 65 61 6e 65 72 2e 70 64 62 } //1 \debug\source\repos\PcCleaner\PcCleaner\obj\Debug\PcCleaner.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Disstl_ADI_MTB_2{
	meta:
		description = "Trojan:BAT/Disstl.ADI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 80 00 00 00 6f 57 00 00 0a 00 06 20 00 01 00 00 6f 58 00 00 0a 00 06 17 6f 59 00 00 0a 00 06 18 6f 5a 00 00 0a 00 06 28 5b 00 00 0a 03 6f 5c 00 00 0a 6f 5d 00 00 0a 00 06 28 5b 00 00 0a 04 6f 5c 00 00 0a 6f 5e 00 00 0a 00 06 06 6f 5f 00 00 0a 06 6f 60 00 00 0a 6f 68 00 00 0a 0b 7e 69 00 00 0a 0c 02 28 } //2
		$a_01_1 = {46 00 75 00 63 00 6b 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //1 Fucked.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Disstl_ADI_MTB_3{
	meta:
		description = "Trojan:BAT/Disstl.ADI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {0d 07 09 16 11 05 6f 2c 00 00 0a 26 16 13 06 2b 11 09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 32 e8 } //2
		$a_03_1 = {08 1f 53 58 0c 00 73 ?? 00 00 0a 7e ?? 00 00 0a 8e 20 91 d2 00 00 58 7e ?? 00 00 0a 8e 20 aa d5 00 00 58 fe 1c 10 00 00 01 1f 41 58 28 } //2
		$a_01_2 = {44 00 69 00 73 00 63 00 6f 00 72 00 64 00 52 00 65 00 73 00 6f 00 6c 00 76 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 DiscordResolver.exe
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}