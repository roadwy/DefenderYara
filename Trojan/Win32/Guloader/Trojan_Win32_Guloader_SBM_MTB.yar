
rule Trojan_Win32_Guloader_SBM_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_81_0 = {62 6c 64 67 72 69 6e 67 65 72 73 2e 63 72 79 } //2 bldgringers.cry
		$a_81_1 = {43 68 6f 72 75 73 73 65 73 32 34 37 2e 73 63 75 } //2 Chorusses247.scu
		$a_81_2 = {69 6e 74 65 72 63 61 6c 61 74 65 64 2e 73 61 73 } //2 intercalated.sas
		$a_81_3 = {73 61 72 64 69 73 6b 65 73 2e 72 65 73 } //2 sardiskes.res
		$a_81_4 = {4f 76 65 72 74 65 67 6e 65 64 65 73 31 36 5c 6e 65 64 62 72 79 64 65 6c 69 67 65 2e 70 61 72 } //1 Overtegnedes16\nedbrydelige.par
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1) >=9
 
}