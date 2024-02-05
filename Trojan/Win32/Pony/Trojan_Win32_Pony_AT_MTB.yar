
rule Trojan_Win32_Pony_AT_MTB{
	meta:
		description = "Trojan:Win32/Pony.AT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {3e 35 72 47 60 a8 98 ff 00 14 e9 39 a3 fc 53 a0 33 a6 32 46 66 ae 98 c9 19 1a 32 32 46 d5 97 41 45 56 00 39 46 99 58 e3 } //02 00 
		$a_01_1 = {29 10 8a 44 6a 2d 14 88 45 22 2a d1 44 a1 a2 34 d6 3d 14 44 1f b1 66 5a 80 00 02 b3 10 c4 56 48 4c 62 2a 10 2e 18 08 0e ac 72 } //00 00 
	condition:
		any of ($a_*)
 
}