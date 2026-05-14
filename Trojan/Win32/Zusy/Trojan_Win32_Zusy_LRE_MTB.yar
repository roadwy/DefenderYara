
rule Trojan_Win32_Zusy_LRE_MTB{
	meta:
		description = "Trojan:Win32/Zusy.LRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 54 04 18 88 d5 f6 d5 88 c6 80 c6 28 20 ee 20 ca 08 f2 88 d5 f6 d5 80 e5 1f 80 e2 e0 08 ea 80 f2 37 88 54 04 18 40 fe c9 83 f8 0b } //20
		$a_01_1 = {88 cd 80 e5 37 88 c6 80 c6 28 80 e6 c8 08 ee 30 d6 88 f2 f6 d2 80 e2 7b 80 e6 84 08 d6 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}