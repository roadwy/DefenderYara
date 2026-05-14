
rule Trojan_Win64_FormBook_AKA_MTB{
	meta:
		description = "Trojan:Win64/FormBook.AKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 84 24 f0 01 00 00 a0 02 00 00 c6 84 24 00 02 00 00 ac c6 84 24 ff 01 00 00 4c c6 84 24 fe 01 00 00 83 c6 84 24 fd 01 00 00 7d c6 84 24 fc 01 00 00 09 c6 84 24 fb 01 00 00 79 c6 84 24 fa 01 00 00 68 c6 84 24 f9 01 00 00 70 c6 84 24 f8 01 00 00 f0 c6 84 24 f7 01 00 00 67 c6 84 24 f6 01 00 00 63 c6 84 24 f5 01 00 00 72 c6 84 24 f4 01 00 00 ec 48 8d 8c 24 f0 01 00 00 48 8d b4 24 07 02 00 00 48 89 f2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}