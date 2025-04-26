
rule Trojan_Win32_Amadey_AMA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c5 81 c0 4c 00 00 00 b9 c2 05 00 00 ba 83 be 29 a5 30 10 40 49 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Amadey_AMA_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 d9 c1 e1 05 c1 e1 05 c1 e9 03 c1 e9 07 81 e9 4a 0e 4c 89 89 cb 59 81 f3 0d 10 fb 79 81 f3 81 81 42 0f 89 d8 5b 01 f0 01 18 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}