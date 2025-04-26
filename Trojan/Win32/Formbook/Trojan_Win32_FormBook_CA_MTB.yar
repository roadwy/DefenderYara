
rule Trojan_Win32_FormBook_CA_MTB{
	meta:
		description = "Trojan:Win32/FormBook.CA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 45 f0 00 84 d7 17 8b 45 e4 89 45 f4 83 7d f0 00 74 16 8b 45 f4 c6 00 00 8b 45 f4 40 89 45 f4 8b 45 f0 48 89 45 f0 eb e4 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_FormBook_CA_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.CA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {fb d9 58 00 00 74 0d c2 55 d0 c2 6b bc bb 87 49 00 00 5a 43 81 c2 4f 2f 01 00 81 eb 4f 77 01 00 05 5f 7a 01 00 b9 45 85 00 00 bb 5b 71 00 00 81 c1 a7 27 01 00 b9 3f 2c 01 00 5a f7 d0 81 e2 19 3d 01 00 4a c2 1f de 42 48 4a c2 1a ad } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}