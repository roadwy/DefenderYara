
rule Trojan_Win32_LightNeuron_D_dha{
	meta:
		description = "Trojan:Win32/LightNeuron.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 76 65 6e 74 33 33 33 } //01 00  Event333
		$a_01_1 = {56 71 56 49 a9 b9 e3 ef e0 ef } //02 00 
		$a_01_2 = {33 36 62 31 66 34 61 2d 38 32 62 39 2d 65 62 30 36 2d 37 63 31 65 2d 39 30 62 34 62 32 64 35 63 32 37 64 } //02 00  36b1f4a-82b9-eb06-7c1e-90b4b2d5c27d
		$a_01_3 = {46 4c 00 53 56 00 42 4c 45 } //02 00 
		$a_01_4 = {c8 cb ca cd cc f6 c2 cc d0 f6 ce cc c7 cc db c8 dd c0 c6 c7 } //02 00 
		$a_01_5 = {12 50 30 74 12 50 31 43 0c 56 64 4a 0a 6a 42 53 } //02 00  倒琰倒䌱嘌䩤樊卂
		$a_03_6 = {04 01 00 00 c6 90 02 03 77 c6 90 02 03 69 c6 90 02 03 6e c6 90 02 03 6d 90 00 } //02 00 
		$a_03_7 = {b9 03 00 1f 00 c6 90 02 03 47 c6 90 02 03 6c 90 00 } //f4 ff 
		$a_01_8 = {73 69 6d 70 6c 65 56 61 6c 69 64 61 74 65 } //00 00  simpleValidate
	condition:
		any of ($a_*)
 
}