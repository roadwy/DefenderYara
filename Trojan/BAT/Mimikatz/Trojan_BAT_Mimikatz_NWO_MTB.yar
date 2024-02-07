
rule Trojan_BAT_Mimikatz_NWO_MTB{
	meta:
		description = "Trojan:BAT/Mimikatz.NWO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 0a 00 "
		
	strings :
		$a_81_0 = {62 72 32 31 72 32 36 37 31 62 32 66 61 6f 77 68 6c } //0a 00  br21r2671b2faowhl
		$a_81_1 = {64 73 61 39 75 68 64 61 37 73 79 74 79 32 64 64 32 } //01 00  dsa9uhda7syty2dd2
		$a_81_2 = {57 97 a2 3f 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 } //01 00 
		$a_81_3 = {44 38 34 46 34 43 31 32 30 30 30 35 46 31 38 33 37 44 43 36 35 43 30 34 31 38 31 46 33 44 41 39 34 36 36 42 31 32 33 46 43 33 36 39 43 33 35 39 } //01 00  D84F4C120005F1837DC65C04181F3DA9466B123FC369C359
		$a_81_4 = {66 74 67 79 68 75 69 6f 70 6f 6a 68 67 } //01 00  ftgyhuiopojhg
		$a_81_5 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}