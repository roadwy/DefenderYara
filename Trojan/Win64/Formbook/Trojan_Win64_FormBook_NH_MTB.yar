
rule Trojan_Win64_FormBook_NH_MTB{
	meta:
		description = "Trojan:Win64/FormBook.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 58 48 89 08 48 8b 4c 24 60 48 89 48 08 8b 4c 24 68 89 c9 48 89 48 10 8b 4c 24 6c 89 c9 48 89 48 18 48 89 c3 b9 04 00 00 00 48 89 cf 48 8b 44 24 30 } //2
		$a_01_1 = {48 8b 44 24 20 48 85 c0 bb 00 00 00 00 48 8b 4c 24 28 48 0f 44 d9 b9 00 00 00 00 48 8b 54 24 40 48 0f 44 ca 48 8b 6c 24 48 48 83 c4 50 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}