
rule Trojan_BAT_SnakeKeylogger_NHG_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 63 32 37 62 31 64 38 63 2d 65 38 34 39 2d 34 62 36 66 2d 61 30 32 30 2d 63 35 32 36 30 66 38 33 62 34 33 65 } //1 $c27b1d8c-e849-4b6f-a020-c5260f83b43e
		$a_81_1 = {4d 61 70 45 64 69 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 } //1 MapEditor.Propertie
		$a_81_2 = {4e 35 47 48 38 47 56 59 33 53 38 34 38 35 38 46 47 30 47 35 48 4a } //1 N5GH8GVY3S84858FG0G5HJ
		$a_81_3 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 2e 41 73 73 65 6d 62 6c 79 } //1 System.Reflection.Assembly
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}