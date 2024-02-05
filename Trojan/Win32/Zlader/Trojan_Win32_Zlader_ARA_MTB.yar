
rule Trojan_Win32_Zlader_ARA_MTB{
	meta:
		description = "Trojan:Win32/Zlader.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {85 c9 7c 2a 8b 35 88 1c 41 00 b8 67 66 66 66 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 8b 15 00 10 41 00 8d 04 80 03 c0 2b d0 8a 04 0a 30 04 0e 41 3b 0d 9c 1c 41 00 76 c9 } //00 00 
	condition:
		any of ($a_*)
 
}