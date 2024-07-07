
rule Trojan_Win64_AsyncRat_RPY_MTB{
	meta:
		description = "Trojan:Win64/AsyncRat.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 c1 c9 08 41 03 c8 8b d3 41 33 c9 c1 ca 08 41 03 d1 41 c1 c0 03 41 33 d2 41 c1 c1 03 44 33 ca 44 33 c1 41 ff c2 41 8b db 44 8b d8 41 83 fa 1b 72 cd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}