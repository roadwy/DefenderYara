
rule Trojan_BAT_AgentTesla_NJD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 34 32 66 65 35 32 39 36 2d 65 30 39 63 2d 34 65 36 34 2d 61 37 31 33 2d 35 64 32 30 31 32 63 39 61 39 65 65 } //01 00  $42fe5296-e09c-4e64-a713-5d2012c9a9ee
		$a_01_1 = {47 61 6d 65 4e 65 74 77 6f 72 6b 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  GameNetwork.Properties
		$a_01_2 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_3 = {54 6f 57 69 6e 33 32 } //01 00  ToWin32
		$a_01_4 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //00 00  ColorTranslator
	condition:
		any of ($a_*)
 
}