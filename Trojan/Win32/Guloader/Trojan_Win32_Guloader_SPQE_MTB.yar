
rule Trojan_Win32_Guloader_SPQE_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SPQE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {73 6f 76 65 68 6a 65 72 74 65 72 6e 65 73 31 2b 30 29 } //01 00  sovehjerternes1+0)
		$a_81_1 = {6d 6f 6e 74 61 67 6e 61 63 40 55 64 64 65 6c 65 67 65 72 69 6e 67 65 72 2e 62 69 67 31 28 30 26 } //01 00  montagnac@Uddelegeringer.big1(0&
		$a_81_2 = {55 74 79 73 6b 65 73 74 72 65 67 20 41 6d 62 75 6c 61 6e 63 65 63 68 61 75 66 66 72 65 72 20 31 } //01 00  Utyskestreg Ambulancechauffrer 1
		$a_81_3 = {73 6f 76 65 68 6a 65 72 74 65 72 6e 65 73 30 } //01 00  sovehjerternes0
		$a_81_4 = {32 30 32 32 31 31 32 33 30 31 34 32 30 36 5a 30 } //00 00  20221123014206Z0
	condition:
		any of ($a_*)
 
}