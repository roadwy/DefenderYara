
rule HackTool_AndroidOS_DroidSheep_A_MTB{
	meta:
		description = "HackTool:AndroidOS/DroidSheep.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 69 6a 61 63 6b 41 63 74 69 76 69 74 79 } //1 HijackActivity
		$a_00_1 = {44 72 6f 69 64 53 68 65 65 70 20 69 73 20 6c 69 73 74 65 6e 69 6e 67 20 66 6f 72 20 73 65 73 73 69 6f 6e 73 } //1 DroidSheep is listening for sessions
		$a_01_2 = {44 52 4f 49 44 53 48 45 45 50 5f 42 4c 41 43 4b 4c 49 53 54 } //1 DROIDSHEEP_BLACKLIST
		$a_00_3 = {53 70 6f 6f 66 69 6e 67 20 77 61 73 20 69 6e 74 65 72 72 75 70 74 65 64 } //1 Spoofing was interrupted
		$a_00_4 = {61 72 70 73 70 6f 6f 66 } //1 arpspoof
		$a_00_5 = {61 75 74 68 54 6f 48 69 6a 61 63 6b } //1 authToHijack
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}