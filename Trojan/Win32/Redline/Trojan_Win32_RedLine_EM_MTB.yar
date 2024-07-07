
rule Trojan_Win32_RedLine_EM_MTB{
	meta:
		description = "Trojan:Win32/RedLine.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 97 20 00 02 00 81 c1 00 01 00 00 c1 e1 08 03 cf 8a 04 0a 88 06 } //2
		$a_01_1 = {80 f1 a3 80 f2 54 88 4c 24 04 0f b6 48 02 88 54 24 05 0f b6 50 03 f6 d1 80 f2 75 88 4c 24 06 } //2
		$a_01_2 = {eb c4 3a 0d f1 c0 36 5e f1 c1 35 bb f1 c1 35 ff f1 c1 35 ff f1 c1 35 ff f1 c1 35 ff f1 c1 35 ff f0 c0 35 fe f1 c1 35 bb f0 c0 36 55 ff bf 3f 04 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}