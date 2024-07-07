
rule Trojan_Win32_RedLineStealer_L_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 07 47 e2 f6 90 09 05 00 f6 17 80 90 00 } //2
		$a_03_1 = {33 c2 83 c1 90 01 01 a9 90 01 04 74 90 09 0c 00 8b 01 ba 90 01 04 03 d0 83 f0 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}