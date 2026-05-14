
rule Trojan_Win32_Guloader_KU_MSR{
	meta:
		description = "Trojan:Win32/Guloader.KU!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {75 6e 64 65 72 76 69 73 6e 69 6e 67 73 70 6c 69 67 74 65 72 73 20 66 6f 72 65 73 68 69 70 20 6f 75 74 68 69 74 } //1 undervisningspligters foreship outhit
		$a_81_1 = {65 6e 65 73 74 75 65 72 73 20 6e 6f 72 64 73 74 70 61 73 73 61 67 65 } //1 enestuers nordstpassage
		$a_81_2 = {61 6d 69 6e 6f 73 79 72 65 6e 20 76 61 72 65 67 6c 64 65 6e 73 2e 65 78 65 } //1 aminosyren varegldens.exe
		$a_81_3 = {74 79 70 68 6f 62 61 63 69 6c 6c 6f 73 69 73 } //1 typhobacillosis
		$a_81_4 = {50 65 72 73 6f 6e 6d 6f 64 65 6c 6c 65 6e 73 2e 61 66 66 } //1 Personmodellens.aff
		$a_81_5 = {61 6e 74 69 6d 6f 6e 6f 70 6f 6c 69 73 6d 2e 68 74 6d } //1 antimonopolism.htm
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}