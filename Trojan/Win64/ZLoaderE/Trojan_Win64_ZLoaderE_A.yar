
rule Trojan_Win64_ZLoaderE_A{
	meta:
		description = "Trojan:Win64/ZLoaderE.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6d 28 72 b3 a3 15 78 e2 91 79 1e ad 31 66 ?? b3 57 28 a4 f5 a5 5e da a1 1b 95 b8 8d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}