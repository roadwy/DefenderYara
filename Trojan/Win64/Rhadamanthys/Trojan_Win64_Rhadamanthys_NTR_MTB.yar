
rule Trojan_Win64_Rhadamanthys_NTR_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 01 d0 44 89 c2 31 ca 88 10 48 8d 00 } //2
		$a_01_1 = {48 8b 45 b0 48 89 45 d0 48 8b 45 d8 48 c1 e0 02 48 8d 50 fc 48 8b 45 90 48 01 d0 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}