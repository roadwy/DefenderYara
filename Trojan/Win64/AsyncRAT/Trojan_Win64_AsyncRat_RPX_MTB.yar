
rule Trojan_Win64_AsyncRat_RPX_MTB{
	meta:
		description = "Trojan:Win64/AsyncRat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 b9 40 00 00 00 31 c9 41 b8 00 10 00 00 ba d3 ca 00 00 ff 10 b9 d0 07 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}