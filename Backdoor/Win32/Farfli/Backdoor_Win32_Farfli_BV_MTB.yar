
rule Backdoor_Win32_Farfli_BV_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {c1 e0 02 33 d0 8b 4d f8 c1 e9 03 8b 45 ec c1 e0 04 33 c8 03 d1 8b 4d f0 33 4d f8 8b 45 fc 83 e0 03 33 45 e8 8b 75 10 8b 04 86 33 45 ec 03 c8 33 d1 8b 4d 08 03 4d fc 0f b6 01 03 c2 8b 4d 08 03 4d fc 88 01 8b 55 08 03 55 fc 0f b6 02 89 45 ec eb } //00 00 
	condition:
		any of ($a_*)
 
}