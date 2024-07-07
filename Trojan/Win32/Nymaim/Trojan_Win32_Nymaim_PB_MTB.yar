
rule Trojan_Win32_Nymaim_PB_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.PB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 fe 88 06 00 00 74 34 6a ff 5f 23 38 83 c0 04 8d 7f cd c1 cf 08 29 cf 83 c7 ff 8d 0f c1 c1 09 d1 c9 6a 00 8f 02 01 3a 8d 52 04 83 c6 04 8d 3d 1e 16 e1 ff 81 c7 c7 21 5f 00 57 c3 } //1
		$a_01_1 = {5a 8b 35 bc 4a 4a 00 56 8d 35 46 7c 21 fd 81 c6 4e bb 1e 03 56 52 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}