
rule Trojan_Win32_Zbot_CL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.CL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 c2 88 06 8a 41 01 46 fe c2 41 84 c0 75 f1 } //01 00 
		$a_01_1 = {ad 66 33 d2 8a d8 32 ff 66 03 d3 8a dc 66 03 db 66 03 d3 c1 c8 10 8a d8 32 ff 66 03 d3 66 c1 ea 02 33 c0 8a c2 8a e2 c1 c0 08 8a c4 ab e2 d1 } //00 00 
	condition:
		any of ($a_*)
 
}