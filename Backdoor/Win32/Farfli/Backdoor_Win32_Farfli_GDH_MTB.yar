
rule Backdoor_Win32_Farfli_GDH_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 5c 24 30 8b 44 24 28 83 c0 01 0f b6 80 90 01 04 88 44 1c 48 8b 44 24 30 8d 68 ff 89 e8 31 d8 f7 d0 09 e8 78 05 e8 90 01 04 83 fd 90 01 01 0f 86 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}