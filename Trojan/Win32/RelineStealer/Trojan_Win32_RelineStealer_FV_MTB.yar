
rule Trojan_Win32_RelineStealer_FV_MTB{
	meta:
		description = "Trojan:Win32/RelineStealer.FV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {a0 7e 4f 00 88 0d 90 01 04 0f b6 05 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 0f be 11 33 d0 a1 90 01 04 03 45 90 01 01 88 10 90 00 } //10
		$a_02_1 = {a0 7e 4f 00 03 05 90 01 04 33 d2 b9 90 01 04 f7 f1 89 15 90 01 04 a1 90 01 04 8a 88 90 01 04 88 0d 90 01 04 a1 94 7e 4f 00 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}