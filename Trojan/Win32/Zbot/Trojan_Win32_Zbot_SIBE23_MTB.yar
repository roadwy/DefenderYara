
rule Trojan_Win32_Zbot_SIBE23_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBE23!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {01 f8 89 c7 89 44 24 90 01 01 be 90 01 04 01 c6 80 38 00 75 90 01 01 8a 0a 88 08 42 40 39 c6 75 90 01 01 90 18 5a 31 c9 8a 2f 32 2a 88 2f fe c1 42 80 f9 90 01 01 75 90 01 01 31 c9 83 ea 90 01 01 47 39 f8 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}