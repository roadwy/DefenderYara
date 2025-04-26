
rule Trojan_Win32_GuLoader_RSW_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 73 74 61 72 74 70 61 72 61 6d 65 74 72 65 74 73 5c 41 6e 61 62 6c 65 70 73 65 73 31 32 34 5c 53 70 69 73 65 62 6c 65 72 } //1 \startparametrets\Anablepses124\Spisebler
		$a_81_1 = {39 39 5c 70 65 72 74 75 72 62 69 6e 67 6c 79 5c 6d 65 74 61 70 6c 61 73 69 73 2e 66 6f 72 } //1 99\perturbingly\metaplasis.for
		$a_81_2 = {5c 74 79 70 68 65 6d 69 61 2e 61 74 6d } //1 \typhemia.atm
		$a_81_3 = {73 79 6e 74 61 6b 73 61 6e 61 6c 79 73 65 72 6e 65 20 63 6f 64 65 76 65 6c 6f 70 } //1 syntaksanalyserne codevelop
		$a_81_4 = {68 61 65 72 76 61 65 72 6b 20 70 65 6e 64 61 6e 74 65 72 } //1 haervaerk pendanter
		$a_81_5 = {74 76 61 6e 67 73 66 75 6c 64 62 79 72 64 65 72 2e 65 78 65 } //1 tvangsfuldbyrder.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}