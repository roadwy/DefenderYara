
rule Trojan_Win32_DCRat_A_AMTB{
	meta:
		description = "Trojan:Win32/DCRat.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {50 45 73 50 45 73 45 50 } //PEsPEsEP  2
		$a_80_1 = {4e 2d 2a 20 70 65 53 70 65 53 65 70 20 } //N-* peSpeSep   2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}