
rule Trojan_Win64_IcedID_DT_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 "
		
	strings :
		$a_01_0 = {44 66 67 6a 6b 67 73 64 66 64 67 68 6a 66 73 61 } //10 Dfgjkgsdfdghjfsa
		$a_01_1 = {49 46 48 4b 57 77 59 74 50 72 43 } //1 IFHKWwYtPrC
		$a_01_2 = {51 7a 74 68 4e 6d 6e 77 6d 71 46 } //1 QzthNmnwmqF
		$a_01_3 = {56 74 47 41 72 55 42 73 46 5a } //1 VtGArUBsFZ
		$a_01_4 = {4d 61 46 56 5a 79 68 6b 4b 4f } //1 MaFVZyhkKO
		$a_01_5 = {47 68 62 61 73 66 6a 6b 6e 62 79 68 6a 61 6a 6b 61 73 } //10 Ghbasfjknbyhjajkas
		$a_01_6 = {41 49 61 4e 59 55 46 66 55 6f 50 } //1 AIaNYUFfUoP
		$a_01_7 = {4e 45 48 56 63 42 49 6b 65 49 56 } //1 NEHVcBIkeIV
		$a_01_8 = {55 66 4b 7a 41 50 6d 53 44 74 7a } //1 UfKzAPmSDtz
		$a_01_9 = {62 70 71 4b 43 47 52 68 78 67 } //1 bpqKCGRhxg
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=14
 
}