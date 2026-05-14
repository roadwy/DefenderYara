
rule Trojan_Win64_Rhadamanthys_NTS_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 b9 cf f7 53 e3 a5 9b c4 20 48 f7 e9 48 89 d6 48 89 d0 48 c1 e8 3f 48 c1 fe 07 48 01 c6 48 03 74 24 } //2
		$a_01_1 = {48 83 ec 28 89 ce 31 c9 ba 01 00 00 00 45 31 c0 45 31 c9 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}