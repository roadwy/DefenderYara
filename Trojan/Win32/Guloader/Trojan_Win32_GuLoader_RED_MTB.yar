
rule Trojan_Win32_GuLoader_RED_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {73 6b 6a 6f 72 74 65 6b 6a 6f 6c 65 6e 73 5c 52 6f 64 65 6f 73 5c 47 6c 61 73 73 69 65 72 } //1 skjortekjolens\Rodeos\Glassier
		$a_81_1 = {25 47 61 76 6c 68 75 73 65 73 32 35 30 25 5c 53 69 6b 73 61 6b 6b 65 5c 47 72 75 73 6e 69 6e 67 65 72 6e 65 73 } //1 %Gavlhuses250%\Siksakke\Grusningernes
		$a_81_2 = {73 74 6f 72 79 65 72 20 63 69 76 69 6c 72 65 74 6c 69 67 65 20 6b 6a 65 72 75 6d 6d 65 6e 65 } //1 storyer civilretlige kjerummene
		$a_81_3 = {74 74 74 72 79 6b 74 20 69 6e 74 65 72 62 72 61 6e 63 68 } //1 tttrykt interbranch
		$a_81_4 = {73 79 6e 74 6f 6e 65 20 61 6e 73 61 6d 6c 69 6e 67 65 6e 2e 65 78 65 } //1 syntone ansamlingen.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}