
rule Trojan_Win32_Minix_SNC_MTB{
	meta:
		description = "Trojan:Win32/Minix.SNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {64 65 74 61 69 6c 76 69 72 6b 73 6f 6d 68 65 64 65 72 20 74 65 73 74 69 73 20 62 65 68 61 6e 64 6c 69 6e 67 73 76 69 72 6b 73 6f 6d 68 65 64 65 72 } //1 detailvirksomheder testis behandlingsvirksomheder
		$a_81_1 = {6d 69 73 63 72 69 70 74 20 66 6e 69 73 74 65 } //1 miscript fniste
		$a_81_2 = {68 6f 79 64 65 6e 69 73 68 6e 65 73 73 20 64 69 73 63 6c 6f 73 69 76 65 2e 65 78 65 } //1 hoydenishness disclosive.exe
		$a_81_3 = {6f 61 73 74 68 6f 75 73 65 20 65 6e 73 72 65 74 74 65 6e 64 65 } //1 oasthouse ensrettende
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}