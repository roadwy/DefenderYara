
rule Trojan_Win32_Cerbu_AMDC_MTB{
	meta:
		description = "Trojan:Win32/Cerbu.AMDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 17 89 d8 88 c0 d9 ff ?? ?? 80 2f ?? 80 07 ?? 89 d8 88 c0 d9 ff ?? ?? 47 e2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}