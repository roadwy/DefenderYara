
rule Trojan_Win64_Rhadamanthys_NTO_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NTO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {5f 70 61 79 6c 6f 61 64 5f 69 6e 69 74 } //1 _payload_init
		$a_01_1 = {48 0f af 44 24 30 48 b9 cf f7 53 e3 a5 9b c4 20 48 f7 e9 48 89 d6 48 89 d0 48 c1 e8 3f 48 c1 fe 07 48 01 c6 48 03 74 24 28 } //1
		$a_01_2 = {48 83 ec 20 89 ce 31 c9 ba 01 00 00 00 45 31 c0 45 31 c9 } //2
		$a_01_3 = {56 48 83 ec 20 31 c9 31 d2 45 31 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=5
 
}