
rule Trojan_Win32_WastedLocker_CB{
	meta:
		description = "Trojan:Win32/WastedLocker.CB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 fc 4a 06 00 68 f4 e0 01 00 e8 } //10
		$a_01_1 = {bb 7f 0d 00 00 bb 7f 0d 00 00 } //10
		$a_01_2 = {c7 45 dc 01 00 00 00 c7 45 b4 01 00 00 00 c7 45 b8 01 00 00 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=20
 
}