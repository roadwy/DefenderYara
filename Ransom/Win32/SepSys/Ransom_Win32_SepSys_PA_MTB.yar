
rule Ransom_Win32_SepSys_PA_MTB{
	meta:
		description = "Ransom:Win32/SepSys.PA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 54 54 45 4e 54 49 4f 4e 21 20 59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 68 61 73 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 20 62 79 20 73 65 70 53 79 73 21 } //1 ATTENTION! Your computer has been infected by sepSys!
		$a_01_1 = {2e 69 6e 69 73 65 70 53 79 73 } //1 .inisepSys
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 61 20 72 61 6e 64 6f 6d 20 6b 65 79 } //1 Your files have been encrypted with a random key
		$a_01_3 = {5c 76 69 72 75 73 54 65 73 74 73 5c 73 65 70 53 79 73 } //1 \virusTests\sepSys
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}