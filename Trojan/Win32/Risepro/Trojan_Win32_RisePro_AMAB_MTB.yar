
rule Trojan_Win32_RisePro_AMAB_MTB{
	meta:
		description = "Trojan:Win32/RisePro.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 4c 9d 00 91 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 91 e9 d1 5b 89 4c 24 28 85 d2 75 90 01 01 f6 c3 01 74 90 01 01 8d 47 fd 3b d8 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}