
rule Trojan_BAT_SnakeKeylogger_DV_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {42 65 61 74 53 61 76 65 72 44 6f 77 6e 6c 6f 61 64 65 72 } //1 BeatSaverDownloader
		$a_81_1 = {4c 6f 67 2e 74 78 74 } //1 Log.txt
		$a_81_2 = {4b 65 79 43 6f 6c 6c 65 63 74 69 6f 6e } //1 KeyCollection
		$a_81_3 = {67 65 74 5f 4b 65 79 73 } //1 get_Keys
		$a_81_4 = {44 72 61 67 6f 6e 46 6f 72 63 65 } //1 DragonForce
		$a_81_5 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}