
rule Trojan_Win32_RootkitSPecter_CB_MTB{
	meta:
		description = "Trojan:Win32/RootkitSPecter.CB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 8d 0c 02 8a 04 02 84 c0 74 06 2c 59 34 0c 88 01 42 3b 54 24 08 7c e5 } //1
		$a_01_1 = {8b 44 24 04 03 c1 8a 10 80 ea 63 80 f2 61 41 3b 4c 24 08 88 10 7c e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}