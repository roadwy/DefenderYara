
rule Trojan_Win64_Cometer_DD_MTB{
	meta:
		description = "Trojan:Win64/Cometer.DD!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 48 98 48 39 45 18 76 54 8b 45 fc 48 98 48 8b 55 28 48 83 ea 01 48 39 d0 75 07 c7 45 fc } //10
		$a_01_1 = {48 01 d0 0f b6 08 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 10 8b 45 f8 4c 63 c0 48 8b 45 10 4c 01 c0 31 ca 88 10 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}