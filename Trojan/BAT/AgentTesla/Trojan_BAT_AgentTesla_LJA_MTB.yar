
rule Trojan_BAT_AgentTesla_LJA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {2b 2a 00 08 09 11 04 6f 90 01 03 0a 13 05 08 09 11 04 6f 90 01 03 0a 13 06 07 06 02 11 06 28 90 01 03 06 d2 9c 00 11 04 17 58 13 04 11 04 17 fe 04 13 07 11 07 2d cb 90 00 } //01 00 
		$a_81_1 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_LJA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.LJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 66 73 64 66 73 64 2e 64 6c 6c 23 } //01 00  #fsdfsd.dll#
		$a_01_1 = {23 68 64 66 66 66 77 74 77 66 66 66 66 66 66 66 67 73 73 73 73 73 64 66 2e 64 6c 6c 23 } //01 00  #hdfffwtwfffffffgsssssdf.dll#
		$a_01_2 = {23 67 74 74 74 74 74 74 77 64 73 23 } //01 00  #gttttttwds#
		$a_01_3 = {23 77 77 77 77 77 77 77 77 77 23 } //01 00  #wwwwwwwww#
		$a_01_4 = {23 66 66 66 73 77 74 66 2e 64 6c 6c 23 } //01 00  #fffswtf.dll#
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_LJA_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.LJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0d 09 2d dc 90 00 } //01 00 
		$a_81_1 = {3f 0e 30 00 30 00 33 00 36 00 30 00 30 00 33 00 32 00 30 00 30 00 33 00 38 00 30 00 30 00 33 00 32 00 30 00 30 00 33 00 37 00 30 00 30 00 33 00 30 00 30 00 30 00 33 00 34 00 30 00 30 00 33 00 34 00 30 00 30 00 33 00 } //01 00  ฿00360032003800320037003000340034003
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //00 00  DownloadData
	condition:
		any of ($a_*)
 
}