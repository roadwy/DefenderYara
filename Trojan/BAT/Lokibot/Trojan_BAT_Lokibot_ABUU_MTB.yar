
rule Trojan_BAT_Lokibot_ABUU_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ABUU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 13 05 2b 18 09 11 05 07 11 05 91 08 11 05 08 8e 69 5d 91 61 d2 9c 11 05 17 58 13 05 11 05 07 8e 69 32 e1 } //4
		$a_01_1 = {42 00 61 00 6c 00 6c 00 47 00 61 00 6d 00 65 00 73 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 BallGamesWindowsFormsApp.Properties.Resources
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}