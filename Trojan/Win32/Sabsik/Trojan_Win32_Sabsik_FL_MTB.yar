
rule Trojan_Win32_Sabsik_FL_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.FL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 08 4a 48 00 4e 4a e8 1a 00 00 00 01 d2 31 07 42 81 c7 02 00 00 00 21 d6 4a 39 df 7c e2 } //01 00 
		$a_01_1 = {8d 04 01 01 d6 8b 00 01 d6 81 e0 ff 00 00 00 21 d2 ba ef 58 3d c8 21 f2 81 c1 01 00 00 00 4e 81 f9 f4 01 00 00 75 05 b9 00 00 00 00 01 d6 } //00 00 
	condition:
		any of ($a_*)
 
}