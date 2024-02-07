
rule Trojan_Win32_Graftor_GNZ_MTB{
	meta:
		description = "Trojan:Win32/Graftor.GNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {a0 34 48 bc 37 35 fd dd b4 95 5b 05 01 f0 9c b2 0c 06 a2 f0 6d 40 d7 51 } //01 00 
		$a_01_1 = {77 39 24 63 66 45 34 } //01 00  w9$cfE4
		$a_01_2 = {40 44 6e 43 57 6b 6a 7a } //00 00  @DnCWkjz
	condition:
		any of ($a_*)
 
}