
rule Trojan_Win64_Rhadamanthys_NRQ_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NRQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_81_0 = {42 43 72 79 70 74 44 65 63 72 79 70 74 } //1 BCryptDecrypt
		$a_01_1 = {69 c0 6d 4e c6 41 b9 cd cc cc cc 05 39 30 00 00 25 ff ff ff 7f 89 } //1
		$a_03_2 = {89 c2 48 8d 05 ?? ?? ?? ?? 31 c1 89 c8 31 d0 eb } //2
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}