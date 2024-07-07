
rule Trojan_Win32_Relinestealer_FA_MTB{
	meta:
		description = "Trojan:Win32/Relinestealer.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {40 24 4d 00 88 0d 90 01 04 0f b6 05 90 01 04 8b 0d 90 01 04 03 4d 90 01 01 0f be 11 33 d0 a1 90 01 04 03 45 f8 88 10 e9 90 01 04 83 3d 90 00 } //10
		$a_02_1 = {34 24 4d 00 a1 90 01 04 8a 88 90 01 04 88 0d 90 01 04 a1 34 24 4d 00 8b 0d 90 01 04 8a 91 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}