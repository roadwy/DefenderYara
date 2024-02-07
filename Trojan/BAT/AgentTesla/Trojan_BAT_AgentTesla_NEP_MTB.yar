
rule Trojan_BAT_AgentTesla_NEP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {63 41 42 70 41 47 34 41 5a 77 41 67 41 48 6b 41 59 51 42 6f 41 47 38 41 62 77 41 75 41 47 4d 41 62 77 42 74 41 44 73 41 49 41 42 77 41 } //01 00  cABpAG4AZwAgAHkAYQBoAG8AbwAuAGMAbwBtADsAIABwA
		$a_81_1 = {41 4f 77 42 77 41 47 6b 41 62 67 42 6e 41 43 41 41 65 51 42 68 41 47 67 41 62 77 42 76 41 43 34 41 59 77 42 76 41 47 30 41 4f 77 41 3d } //01 00  AOwBwAGkAbgBnACAAeQBhAGgAbwBvAC4AYwBvAG0AOwA=
		$a_81_2 = {68 74 74 70 73 3a 2f 2f 61 6e 61 72 63 68 79 72 73 70 73 2e 6c 69 76 65 2f } //01 00  https://anarchyrsps.live/
		$a_01_3 = {24 35 34 65 32 35 62 36 34 2d 31 64 36 32 2d 34 30 65 61 2d 38 38 63 64 2d 31 37 32 30 64 61 30 64 34 33 32 37 } //01 00  $54e25b64-1d62-40ea-88cd-1720da0d4327
		$a_01_4 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_6 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //00 00  GetCurrentProcess
	condition:
		any of ($a_*)
 
}