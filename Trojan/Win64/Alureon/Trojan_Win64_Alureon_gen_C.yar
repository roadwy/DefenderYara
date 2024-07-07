
rule Trojan_Win64_Alureon_gen_C{
	meta:
		description = "Trojan:Win64/Alureon.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 b9 00 02 00 00 b2 28 44 89 64 24 90 01 22 b8 43 44 00 00 66 39 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}