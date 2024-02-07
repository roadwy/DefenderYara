
rule Trojan_Win32_Zloader_MBHS_MTB{
	meta:
		description = "Trojan:Win32/Zloader.MBHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 72 63 74 76 79 62 44 72 63 74 76 79 } //01 00  GrctvybDrctvy
		$a_01_1 = {59 63 74 76 79 62 45 63 72 74 76 79 } //01 00  YctvybEcrtvy
		$a_01_2 = {66 72 67 74 68 79 2e 64 6c 6c } //00 00  frgthy.dll
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zloader_MBHS_MTB_2{
	meta:
		description = "Trojan:Win32/Zloader.MBHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 38 36 2e 64 6c 6c 00 5f 61 40 34 } //01 00  㡸⸶汤l慟㑀
		$a_01_1 = {4b 73 68 42 6e 77 6b 6c 71 64 7c 65 48 6e 66 6d 67 51 63 70 71 61 6b 6f 71 } //01 00  KshBnwklqd|eHnfmgQcpqakoq
		$a_01_2 = {46 6c 65 68 63 63 72 6c 42 6b 6c 49 6a 68 75 6b 68 6e 6f 79 67 5b 6d 65 } //01 00  FlehccrlBklIjhukhnoyg[me
		$a_01_3 = {4b 72 6d 75 68 61 68 6e 55 66 61 7c 6d 6e 6c 46 67 6d 5a 77 6d 6d 45 66 77 6f 74 } //00 00  KrmuhahnUfa|mnlFgmZwmmEfwot
	condition:
		any of ($a_*)
 
}