
rule Trojan_Win32_Yakes_ASG_MTB{
	meta:
		description = "Trojan:Win32/Yakes.ASG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {d8 e6 6e 24 d0 ee 18 0e 5e 05 1c 9d ba 7a 5d de 9c 2f c0 42 c6 a3 9d 14 2c 4e e8 82 60 f3 76 d2 5a 5c ee 64 fe b8 a3 dd fc af d6 e5 25 2c f4 65 d3 ab 18 77 84 db 05 51 0c 0d dc 33 0e } //02 00 
		$a_01_1 = {94 e3 39 8c 2e 16 02 60 93 48 9e 95 19 01 f7 7c e4 ef 50 e2 43 31 25 de fb c4 85 be c2 04 fe 3d a2 be 85 aa ef c9 02 39 a2 f4 ba 65 46 30 39 e8 fb 72 4d 5f e7 02 d4 07 bf 67 ff 5c 10 4c 1b 40 } //01 00 
		$a_01_2 = {40 08 00 00 50 3c 00 00 00 00 00 00 30 81 00 00 10 00 00 00 50 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}