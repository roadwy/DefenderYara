
rule Trojan_Win64_DllHijack_GTV_MTB{
	meta:
		description = "Trojan:Win64/DllHijack.GTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 00 32 00 30 00 32 00 35 00 00 00 00 00 00 00 72 64 66 59 2a 26 36 38 93 05 b8 32 a3 09 d7 } //10
		$a_80_1 = {34 37 63 33 32 30 32 35 } //47c32025  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}