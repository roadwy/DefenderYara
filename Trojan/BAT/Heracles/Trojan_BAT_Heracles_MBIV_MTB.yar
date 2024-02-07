
rule Trojan_BAT_Heracles_MBIV_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 63 63 37 66 61 64 30 33 2d 38 31 36 65 2d 34 33 32 63 2d 39 62 39 32 2d 30 30 31 66 32 64 33 35 38 33 37 39 } //01 00  $cc7fad03-816e-432c-9b92-001f2d358379
		$a_01_1 = {73 65 72 76 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //01 00  server.Resources.resource
		$a_01_2 = {43 6f 6e 66 75 73 65 64 42 79 41 74 74 72 69 62 75 74 65 } //01 00  ConfusedByAttribute
		$a_01_3 = {73 65 72 76 65 72 31 2e 65 78 65 } //00 00  server1.exe
	condition:
		any of ($a_*)
 
}