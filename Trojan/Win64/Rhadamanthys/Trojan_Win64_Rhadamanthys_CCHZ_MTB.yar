
rule Trojan_Win64_Rhadamanthys_CCHZ_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 8a 04 1e 41 32 03 42 88 04 19 49 83 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}