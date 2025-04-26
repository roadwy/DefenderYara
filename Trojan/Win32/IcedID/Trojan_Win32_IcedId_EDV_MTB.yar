
rule Trojan_Win32_IcedId_EDV_MTB{
	meta:
		description = "Trojan:Win32/IcedId.EDV!MTB,SIGNATURE_TYPE_PEHSTR,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4d e7 2b c1 0f b6 55 e7 03 d0 88 55 e7 } //10
		$a_01_1 = {83 ea 04 33 c0 2b 55 e8 1b 45 ec 88 55 e7 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}