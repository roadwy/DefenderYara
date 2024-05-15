
rule Trojan_Win32_Dapato_ADA_MTB{
	meta:
		description = "Trojan:Win32/Dapato.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {be f8 93 8a 00 b8 38 93 8a 00 0f 45 f0 33 ff 80 3e 00 74 49 8b d6 8d 59 28 52 8d 4d d8 } //01 00 
		$a_01_1 = {8b ec 51 8d 45 fc 50 68 40 9f 7c 00 68 00 00 00 80 ff 15 74 70 7c 00 f7 d8 1a c0 fe c0 8b e5 5d } //00 00 
	condition:
		any of ($a_*)
 
}