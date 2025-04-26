
rule Trojan_Win32_Urelas_HNS_MTB{
	meta:
		description = "Trojan:Win32/Urelas.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 00 41 00 53 00 50 00 4f 00 4b 00 45 00 52 00 00 00 00 00 b0 04 02 00 ff ff ff ff 0c 00 00 00 5c d5 8c ac 84 c7 20 00 7c b7 a4 c2 a0 bc 00 ac } //1
		$a_01_1 = {70 00 6f 00 6b 00 65 00 72 00 37 00 00 00 00 00 b0 04 02 00 ff ff ff ff 07 00 00 00 5c d5 8c ac 84 c7 20 00 37 } //1
		$a_01_2 = {44 00 75 00 65 00 6c 00 50 00 6f 00 6b 00 65 00 72 00 00 00 b0 04 02 00 ff ff ff ff 07 00 00 00 5c d5 8c ac 84 c7 20 00 de b9 ec d3 e4 ce 00 00 b0 04 02 00 ff ff ff ff 09 00 00 00 4e 00 65 00 77 00 62 00 61 00 64 00 75 00 67 00 69 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}