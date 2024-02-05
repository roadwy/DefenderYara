
rule TrojanSpy_BAT_KeyLogger_ARA_MTB{
	meta:
		description = "TrojanSpy:BAT/KeyLogger.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_80_0 = {63 3a 5c 55 73 65 72 73 5c 6c 61 62 5c 44 65 73 6b 74 6f 70 5c 6c 61 62 5c 6b 65 79 6c 6f 67 2e 74 78 74 } //c:\Users\lab\Desktop\lab\keylog.txt  02 00 
		$a_80_1 = {4b 45 59 4c 4f 47 47 45 52 } //KEYLOGGER  00 00 
	condition:
		any of ($a_*)
 
}