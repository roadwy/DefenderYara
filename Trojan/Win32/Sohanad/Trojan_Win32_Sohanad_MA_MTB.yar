
rule Trojan_Win32_Sohanad_MA_MTB{
	meta:
		description = "Trojan:Win32/Sohanad.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {39 ce cd d6 6b 19 09 96 fb c1 56 23 6b 07 c0 a3 11 e2 3c f2 b5 82 f0 2c 52 c1 0f 82 a0 ee e5 0c } //05 00 
		$a_01_1 = {83 68 c9 66 aa e3 23 c4 f1 e8 df ff 3e 14 08 70 df bd 1c d0 77 76 b3 97 e9 92 59 2e d1 b8 39 f2 } //01 00 
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //01 00 
		$a_01_3 = {44 65 76 69 63 65 49 6f 43 6f 6e 74 72 6f 6c } //01 00 
		$a_01_4 = {4c 6f 63 6b 53 65 72 76 69 63 65 44 61 74 61 62 61 73 65 } //00 00 
	condition:
		any of ($a_*)
 
}