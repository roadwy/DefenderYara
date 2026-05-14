
rule Trojan_Win64_Rhadamanthys_RRI_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.RRI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 02 b8 48 c1 e9 25 6b c9 64 29 c8 8d 4c 05 64 83 c0 64 89 0f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}