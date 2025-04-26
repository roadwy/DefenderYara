
rule Backdoor_Win32_Berbew_M_MTB{
	meta:
		description = "Backdoor:Win32/Berbew.M!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 85 d0 fe ff ff 89 c3 31 d8 89 c3 29 d8 89 c3 f7 e3 89 85 cc fe ff ff } //10
		$a_01_1 = {b8 46 3c 00 00 f7 e3 89 85 d8 fe ff ff 89 c3 f7 e3 89 85 d4 fe ff ff 89 c3 81 c3 41 7d 00 00 68 04 01 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}