
rule Trojan_BAT_AgentTesla_NJK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {24 64 35 34 36 66 62 66 66 2d 30 32 35 35 2d 34 34 30 66 2d 39 62 64 62 2d 37 66 39 65 39 38 62 36 36 62 36 39 } //0a 00  $d546fbff-0255-440f-9bdb-7f9e98b66b69
		$a_01_1 = {24 62 32 38 33 35 33 65 63 2d 61 38 64 37 2d 34 64 30 33 2d 61 39 31 36 2d 63 30 31 33 62 38 63 36 36 33 61 65 } //01 00  $b28353ec-a8d7-4d03-a916-c013b8c663ae
		$a_01_2 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_3 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00  ColorTranslator
		$a_01_4 = {54 6f 57 69 6e 33 32 } //00 00  ToWin32
	condition:
		any of ($a_*)
 
}