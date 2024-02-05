
rule Trojan_BAT_AveMariaRAT_NT_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {d5 02 28 09 0f 00 00 00 d0 00 20 00 06 00 00 01 00 00 00 63 00 00 00 65 00 00 00 b0 00 00 00 0a 01 00 00 20 00 00 00 97 } //01 00 
		$a_01_1 = {68 50 66 64 73 66 68 64 73 64 72 6f 64 73 63 65 73 73 } //01 00 
		$a_01_2 = {6c 70 42 61 73 66 73 64 73 64 66 65 64 64 66 68 73 41 64 64 72 65 73 73 } //01 00 
		$a_01_3 = {6c 70 42 66 64 73 64 68 73 64 73 64 73 66 75 66 66 65 72 } //01 00 
		$a_01_4 = {43 6f 70 6f 6f 6f 70 6f 6f 6f 70 6f 70 6f 6f 6f 70 70 70 70 70 71 70 6f 6f 6f 70 6f 6f } //01 00 
		$a_01_5 = {41 74 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AveMariaRAT_NT_MTB_2{
	meta:
		description = "Trojan:BAT/AveMariaRAT.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 ed 06 c7 06 c7 06 c7 06 c7 06 c7 06 ba 06 ec 06 fb 06 ed 06 ba 06 c7 06 fa 06 c7 06 f4 06 d4 06 cf 06 e8 06 ed } //01 00 
		$a_01_1 = {c7 06 c7 06 cd 06 d0 06 ee 06 e9 06 da 06 c8 06 ff 06 fc 06 e7 06 c7 06 f4 06 d3 06 c9 06 c7 06 c7 06 c7 06 d1 06 c9 06 ee 06 f5 06 da 06 c9 06 d8 06 cb 06 d0 06 d8 06 d7 } //01 00 
		$a_01_2 = {ca 06 cb 06 c7 06 d2 06 ed 06 c7 06 00 07 c7 06 c9 06 ba 06 c7 06 d3 06 c7 06 c7 06 fb 06 c7 06 ca 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 06 c7 } //01 00 
		$a_01_3 = {39 32 62 36 33 36 65 37 2d 37 66 38 30 2d 34 61 33 35 2d 62 66 35 39 2d 30 38 39 65 33 30 62 30 64 64 37 32 } //01 00 
		$a_01_4 = {43 50 54 31 38 35 } //00 00 
	condition:
		any of ($a_*)
 
}