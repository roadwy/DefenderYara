
rule Trojan_Win32_Zbot_MTB{
	meta:
		description = "Trojan:Win32/Zbot!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 57 53 8b 5d 94 85 df c1 c3 18 8b 0b 8b 45 80 85 c3 c1 c8 02 3b c8 0f 85 bb fb ff ff } //1
		$a_01_1 = {33 c8 33 ff ba 00 00 fc 03 c1 ca 1a e9 b7 01 00 00 } //2
		$a_01_2 = {8b 45 a4 85 c3 d1 c0 03 f0 8b 16 c1 c2 17 83 e2 09 03 ca 4b 89 0f } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=5
 
}