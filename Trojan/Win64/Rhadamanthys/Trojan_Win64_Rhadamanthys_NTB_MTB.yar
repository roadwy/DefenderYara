
rule Trojan_Win64_Rhadamanthys_NTB_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {b8 00 00 b9 ?? 00 00 00 ff d6 b9 ?? 00 00 00 ff d6 b9 ?? 00 00 00 ff d6 b9 ?? 00 00 00 ff d6 b9 } //2
		$a_03_1 = {48 69 c0 e8 03 00 00 48 8b 8c 24 ?? 00 00 00 48 89 c2 48 09 ca 48 c1 ea 20 } //3
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}