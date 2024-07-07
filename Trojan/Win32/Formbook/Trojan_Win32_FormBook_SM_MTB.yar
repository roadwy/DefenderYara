
rule Trojan_Win32_FormBook_SM_MTB{
	meta:
		description = "Trojan:Win32/FormBook.SM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 34 24 4a 5b 7d 82 81 3c 24 89 2a ac 60 81 3c 24 af 1f b3 ac 8f 04 08 81 3c 24 1d 1d 44 49 81 7d 00 40 00 b2 8c 01 d9 81 3c 24 33 4b 73 1c 81 7d 00 b2 3b da 19 81 f9 30 73 00 00 75 a3 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}