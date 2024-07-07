
rule TrojanDropper_Win32_Tracur_gen_G{
	meta:
		description = "TrojanDropper:Win32/Tracur.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {75 06 83 7d 00 00 74 79 55 89 e5 80 7d 0c 01 75 22 ba 90 01 04 56 52 b9 90 01 04 be 8e 90 01 01 00 00 03 75 08 81 f1 90 01 04 d3 ca 30 36 ac e2 f9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}