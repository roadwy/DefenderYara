
rule Trojan_BAT_AsyncRAT_BGE_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 00 10 00 00 8d 04 00 00 01 13 05 38 3f 00 00 00 fe 0c 01 00 45 01 00 00 00 21 00 00 00 38 1c 00 00 00 11 04 11 05 16 11 05 8e 69 6f 0b 00 00 0a 25 13 06 16 3d 05 00 00 00 38 35 00 00 00 11 08 11 05 16 11 06 6f 0c 00 00 0a 38 d3 ff ff ff 38 ce ff ff ff 20 00 00 00 00 7e 4a 00 00 04 7b 35 00 00 04 3a ac ff ff ff 26 20 00 00 00 00 38 a1 ff ff ff dd 62 00 00 00 } //2
		$a_81_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_2 = {24 64 30 66 32 38 64 64 35 2d 36 34 32 66 2d 34 65 34 33 2d 39 36 65 39 2d 34 39 64 31 35 64 35 62 35 61 38 33 } //1 $d0f28dd5-642f-4e43-96e9-49d15d5b5a83
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}