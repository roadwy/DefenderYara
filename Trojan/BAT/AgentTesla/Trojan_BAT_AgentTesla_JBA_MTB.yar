
rule Trojan_BAT_AgentTesla_JBA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JBA!MTB,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 37 38 36 63 36 65 38 2d 33 37 63 30 2d 34 35 61 61 2d 61 35 61 31 2d 35 66 64 63 36 39 36 35 31 31 64 38 } //01 00  3786c6e8-37c0-45aa-a5a1-5fdc696511d8
		$a_01_1 = {53 70 6c 69 74 } //01 00  Split
		$a_01_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_4 = {51 41 5a 58 53 57 45 44 43 56 46 52 54 47 42 4e 48 59 } //01 00  QAZXSWEDCVFRTGBNHY
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //01 00  FromBase64CharArray
		$a_01_6 = {49 49 49 49 49 49 49 55 48 47 46 44 46 43 44 43 48 48 } //01 00  IIIIIIIUHGFDFCDCHH
		$a_01_7 = {75 4e 6f 74 65 70 61 64 } //01 00  uNotepad
		$a_01_8 = {53 41 44 46 47 48 4a 4e 45 52 46 47 54 42 57 53 44 45 43 } //01 00  SADFGHJNERFGTBWSDEC
		$a_01_9 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_10 = {55 4a 4e 42 48 59 54 47 56 43 46 54 52 44 58 } //00 00  UJNBHYTGVCFTRDX
	condition:
		any of ($a_*)
 
}