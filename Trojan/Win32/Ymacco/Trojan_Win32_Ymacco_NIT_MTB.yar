
rule Trojan_Win32_Ymacco_NIT_MTB{
	meta:
		description = "Trojan:Win32/Ymacco.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 89 d0 40 8b 04 85 30 5f 41 00 25 ff ff ff 7f 8b 1c 95 30 5f 41 00 81 e3 00 00 00 80 09 d8 89 c1 89 d0 05 8d 01 00 00 89 cb d1 eb 8b 34 85 30 5f 41 00 31 de 89 c8 83 e0 01 8b 04 85 20 17 41 00 31 c6 89 34 95 30 5f 41 00 81 fa e2 00 00 00 7c ae } //2
		$a_01_1 = {42 89 d0 48 8b 0c 85 30 5f 41 00 89 c8 c1 e8 1e 31 c8 69 c0 65 89 07 6c 01 d0 89 04 95 30 5f 41 00 81 fa 6f 02 00 00 7c d7 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}