
rule Trojan_Win32_Vidar_IP_MTB{
	meta:
		description = "Trojan:Win32/Vidar.IP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c7 c1 e8 05 03 44 24 28 8b cf c1 e1 04 03 4c 24 2c 8d 14 2f 33 c1 33 c2 2b d8 8b c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}