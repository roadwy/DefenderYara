
rule Trojan_Win32_SelfDel_CB_MTB{
	meta:
		description = "Trojan:Win32/SelfDel.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 f0 2b 35 90 02 04 81 f6 90 02 04 2b 75 08 33 f3 89 35 90 02 04 8b 7d 08 81 ef 90 02 04 e9 90 00 } //2
		$a_03_1 = {2b 55 0c 33 d3 2b 15 90 02 04 83 f2 90 01 01 89 15 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}