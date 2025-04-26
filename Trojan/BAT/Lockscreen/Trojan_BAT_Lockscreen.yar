
rule Trojan_BAT_Lockscreen{
	meta:
		description = "Trojan:BAT/Lockscreen,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 61 73 74 61 74 75 20 68 61 73 20 6c 6f 63 6b 65 64 20 79 6f 75 72 20 63 6f 6d 70 74 75 65 72 20 66 6f 72 20 75 73 69 6e 67 20 6c 65 61 6b 65 64 20 73 6f 66 74 77 61 72 65 21 } //1 Tastatu has locked your comptuer for using leaked software!
		$a_01_1 = {54 68 69 73 20 70 6f 72 67 72 61 6d 20 68 61 73 20 64 69 73 61 62 6c 65 64 20 74 61 73 6b 20 6d 61 6e 61 67 65 72 20 61 6e 64 20 61 6e 74 69 76 69 72 75 73 65 73 2e } //1 This porgram has disabled task manager and antiviruses.
		$a_01_2 = {5c 54 61 73 74 61 74 75 5c 6f 62 6a 5c 44 65 62 75 67 5c 54 61 73 74 61 74 75 2e 70 64 62 } //1 \Tastatu\obj\Debug\Tastatu.pdb
		$a_01_3 = {4c 6f 63 6b 20 54 79 70 65 20 4d 65 61 6e 69 6e 67 3a 20 55 6e 62 72 65 61 6b 61 62 6c 65 20 4c 6f 63 6b } //1 Lock Type Meaning: Unbreakable Lock
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}