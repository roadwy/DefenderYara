
rule Trojan_Win64_Remcos_RP_MTB{
	meta:
		description = "Trojan:Win64/Remcos.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,ffffffcd 00 ffffffcd 00 07 00 00 "
		
	strings :
		$a_01_0 = {4b 72 6f 6e 75 73 2e 65 78 65 } //100 Kronus.exe
		$a_01_1 = {4b 72 6f 6e 75 73 2e 64 6c 6c } //100 Kronus.dll
		$a_01_2 = {63 74 78 2d 2d 2d 2d 20 5b 20 68 69 6a 61 63 6b 20 5d } //1 ctx---- [ hijack ]
		$a_01_3 = {5b 20 4b 65 65 70 55 6e 77 69 6e 64 69 6e 67 20 5d } //1 [ KeepUnwinding ]
		$a_01_4 = {62 63 72 79 70 74 2e 64 6c 6c } //1 bcrypt.dll
		$a_80_5 = {50 52 4f 43 45 53 53 4f 52 5f 43 4f 55 4e 54 } //PROCESSOR_COUNT  1
		$a_01_6 = {61 6e 6f 6e 79 6d 6f 75 73 20 6e 61 6d 65 73 70 61 63 65 27 } //1 anonymous namespace'
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1+(#a_01_6  & 1)*1) >=205
 
}