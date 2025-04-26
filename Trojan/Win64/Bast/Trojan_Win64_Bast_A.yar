
rule Trojan_Win64_Bast_A{
	meta:
		description = "Trojan:Win64/Bast.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 73 69 64 65 6c 6f 61 64 2e 70 64 62 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}