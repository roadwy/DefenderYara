
rule TrojanDropper_Win32_Tracur_gen_H{
	meta:
		description = "TrojanDropper:Win32/Tracur.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 7d 0c 01 75 27 ba 90 01 04 56 52 b9 90 01 04 31 d1 be 90 01 01 90 90 00 00 81 f1 90 01 04 03 75 08 d3 ca 83 fa 00 30 36 ac e2 f6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}