
rule PWS_Win32_Zbot_gen_P{
	meta:
		description = "PWS:Win32/Zbot.gen!P,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {57 8b fc 83 ec 28 c7 44 24 08 00 00 00 00 c7 44 24 20 00 00 00 00 c7 44 24 1c 90 01 04 6a 77 b8 90 01 04 ff 10 29 44 24 1c be 90 01 04 89 74 24 14 8b 74 24 14 8a 5c 24 1c 39 44 24 08 75 02 28 1e ff 44 24 14 be 90 01 04 39 74 24 14 7f 2f c1 6c 24 1c 08 ff 44 24 20 83 7c 24 20 04 75 d1 c7 44 24 20 00 00 00 00 c7 44 24 1c 90 01 04 6a 77 b8 90 01 04 ff 10 29 44 24 1c eb b2 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}