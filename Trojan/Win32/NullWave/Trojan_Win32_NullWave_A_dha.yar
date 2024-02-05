
rule Trojan_Win32_NullWave_A_dha{
	meta:
		description = "Trojan:Win32/NullWave.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {fd ac fe 8c 06 cd ac e9 d0 4f 7e 10 fb 35 41 56 } //01 00 
		$a_01_1 = {ac ac e7 da 4d 9f a0 ea cb 3e 79 06 d7 6e 43 54 } //01 00 
		$a_01_2 = {99 7a e0 80 af 2a 36 6a 27 d5 a4 c0 db } //01 00 
		$a_01_3 = {a5 32 f3 dc a1 79 18 25 72 f9 bb c6 f4 b5 8b 64 } //00 00 
	condition:
		any of ($a_*)
 
}