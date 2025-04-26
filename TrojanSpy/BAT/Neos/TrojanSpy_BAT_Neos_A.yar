
rule TrojanSpy_BAT_Neos_A{
	meta:
		description = "TrojanSpy:BAT/Neos.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 00 6b 00 79 00 4e 00 65 00 6f 00 73 00 20 00 56 00 31 00 2e 00 30 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 45 00 6e 00 67 00 69 00 6e 00 65 00 20 00 53 00 74 00 61 00 72 00 74 00 65 00 64 00 20 00 53 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 6c 00 79 00 21 00 } //1 SkyNeos V1.0 Keylogger Engine Started Successfully!
		$a_01_1 = {56 00 69 00 63 00 74 00 69 00 6d 00 20 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 4e 00 61 00 6d 00 65 00 3a 00 } //1 Victim Computer Name:
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}