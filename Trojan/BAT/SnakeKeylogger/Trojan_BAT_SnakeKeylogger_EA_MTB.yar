
rule Trojan_BAT_SnakeKeylogger_EA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_00_0 = {24 36 64 35 33 64 38 34 36 2d 37 34 33 37 2d 34 63 61 30 2d 62 65 65 30 2d 61 61 32 39 32 65 65 63 64 35 31 61 } //10 $6d53d846-7437-4ca0-bee0-aa292eecd51a
		$a_81_1 = {44 69 61 6c 6f 67 73 4c 69 62 } //1 DialogsLib
		$a_81_2 = {00 58 58 58 58 58 58 00 } //1 堀塘塘X
		$a_81_3 = {72 65 2e 74 78 74 } //1 re.txt
		$a_81_4 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=15
 
}