
rule Trojan_Win64_Rhadamanthys_NTT_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 c2 48 8b 45 10 89 10 8b 55 ec 8b 45 f4 31 c2 48 8b 45 18 89 10 8b 55 e8 8b 45 f4 31 c2 48 8b 45 20 89 10 8b 55 e4 8b 45 f4 31 c2 } //2
		$a_01_1 = {89 45 a4 8b 55 94 8b 45 a4 01 d0 89 45 94 8b 55 84 8b 45 94 31 d0 89 45 84 8b 45 84 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}