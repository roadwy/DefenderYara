
rule Trojan_Win64_Rhadamanthys_BS_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {a9 05 89 09 41 0d 11 11 d9 14 35 16 f5 19 b5 1d 6d 21 1d 25 } //3
		$a_01_1 = {48 83 ec 38 48 8d 4c 24 28 e8 } //1
		$a_01_2 = {6a 09 6b 31 6b 59 6b 81 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}