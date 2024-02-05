
rule Trojan_Win32_Kimsuk_C_dha{
	meta:
		description = "Trojan:Win32/Kimsuk.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 4c 10 ff 8a 1c 10 32 d9 88 1c 10 48 85 c0 7f ef 8a 02 5f 34 ac 5e 88 02 c6 04 2a 00 } //01 00 
		$a_01_1 = {ff b0 f6 a2 f5 b4 e6 a3 ff bc d3 ba d4 a7 d3 b2 d5 b0 c2 9e c8 ad df ac c5 aa c4 f1 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}