
rule Trojan_Win32_Tnega_BC_MTB{
	meta:
		description = "Trojan:Win32/Tnega.BC!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 07 d2 c5 36 66 8b 08 85 e7 81 c7 02 00 00 00 f9 66 85 c0 66 f7 c4 55 0f 66 89 0f 66 0f b3 f9 66 c1 e9 83 8d ad fc ff ff ff 0f 9e c5 c1 f1 c1 66 0f ba f1 8a 8b 4c 25 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}