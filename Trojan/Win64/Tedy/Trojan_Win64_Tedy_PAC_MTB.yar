
rule Trojan_Win64_Tedy_PAC_MTB{
	meta:
		description = "Trojan:Win64/Tedy.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 0f b6 06 48 83 c6 02 41 88 04 10 48 8d 88 00 01 00 00 48 c1 e1 08 48 03 ca 48 ff c2 42 88 3c 11 48 81 fa 00 01 00 00 7c d7 ff c7 49 81 c0 00 01 00 00 81 ff 00 01 00 00 7c c4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}