
rule Trojan_Win32_Tedy_BAB_MTB{
	meta:
		description = "Trojan:Win32/Tedy.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 bc 24 c0 00 00 00 03 6c 24 48 8b 4c 24 28 33 84 24 b0 00 00 00 33 94 24 a4 00 00 00 c1 c7 08 89 ac 24 dc 00 00 00 c1 c1 0c 89 7c 24 10 8b 7c 24 1c c1 c0 0c 89 4c 24 28 01 8c 24 f4 00 00 00 8b 4c 24 30 89 44 24 68 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}