
rule Trojan_Win32_ShipUp_ASF_MTB{
	meta:
		description = "Trojan:Win32/ShipUp.ASF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 f7 d2 8d bf fc ff ff ff 8b 17 66 f7 c2 4c 53 f5 33 d3 f8 0f ca f9 c1 ca 03 e9 d6 3f 07 00 89 55 04 b9 c5 69 e5 57 89 45 08 0f bf cd e9 } //1
		$a_01_1 = {81 f2 2f 45 12 62 66 f7 c6 59 1c 85 d2 f7 d2 81 f2 69 70 62 50 85 cb 33 da } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}