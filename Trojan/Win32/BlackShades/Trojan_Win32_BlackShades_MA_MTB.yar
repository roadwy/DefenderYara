
rule Trojan_Win32_BlackShades_MA_MTB{
	meta:
		description = "Trojan:Win32/BlackShades.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {f2 17 4d 96 ab ef 86 81 3d 67 66 } //03 00 
		$a_01_1 = {40 7e 7e 40 4d 69 63 72 6f 73 6f 66 74 40 7e 7e 40 33 40 7e 7e 40 7c 4f 4e 7c 40 7e 7e 40 0d 0a } //03 00 
		$a_01_2 = {f6 0c 38 73 37 0d 38 73 68 3b 3a 73 e4 d8 37 73 a3 6d 38 73 fa 98 36 73 c6 5a 37 73 f2 a0 2a 73 0d 99 36 73 0b 98 36 73 54 45 38 73 4b 7b 39 73 } //03 00 
		$a_81_3 = {6a 6b 62 76 69 65 70 } //00 00 
	condition:
		any of ($a_*)
 
}