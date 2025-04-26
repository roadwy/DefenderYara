
rule Backdoor_Linux_Gafgyt_AM_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AM!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 50 44 61 50 44 79 50 44 66 50 44 67 50 44 74 } //1 gPDaPDyPDfPDgPDt
		$a_01_1 = {47 50 44 45 50 44 54 50 44 20 50 44 2f 50 44 66 50 44 75 50 44 63 50 44 6b 50 44 31 50 44 68 50 44 65 50 44 78 50 44 } //1 GPDEPDTPD PD/PDfPDuPDcPDkPD1PDhPDePDxPD
		$a_01_2 = {47 50 44 45 50 44 54 50 44 4c 50 44 4f 50 44 43 50 44 41 50 44 4c 50 44 49 50 44 50 } //1 GPDEPDTPDLPDOPDCPDAPDLPDIPDP
		$a_01_3 = {50 44 72 50 44 6d 50 44 20 50 44 2d 50 44 72 50 44 66 50 44 20 50 44 7a 50 44 } //1 PDrPDmPD PD-PDrPDfPD PDzPD
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}