
rule Trojan_Win32_Zbot_BM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 74 a7 fa 47 46 21 d6 31 3b 42 89 f2 42 81 c3 02 00 00 00 be 3a 6f 29 95 29 f6 39 cb } //01 00 
		$a_01_1 = {8a 07 81 c2 01 00 00 00 88 01 09 d2 89 d3 89 d3 41 09 db 89 da 81 c7 02 00 00 00 81 ea 02 1c d7 f3 42 21 db 39 f7 } //00 00 
	condition:
		any of ($a_*)
 
}