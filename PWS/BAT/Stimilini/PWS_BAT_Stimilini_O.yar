
rule PWS_BAT_Stimilini_O{
	meta:
		description = "PWS:BAT/Stimilini.O,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 00 6e 00 70 00 61 00 69 00 64 00 20 00 65 00 76 00 61 00 6c 00 75 00 61 00 74 00 69 00 6f 00 6e 00 20 00 63 00 6f 00 70 00 79 00 20 00 6f 00 66 00 20 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 20 00 54 00 75 00 6e 00 65 00 72 00 20 00 32 00 20 00 28 00 77 00 77 00 77 00 2e 00 68 00 65 00 61 00 76 00 65 00 6e 00 74 00 6f 00 6f 00 6c 00 73 00 2e 00 63 00 6f 00 6d 00 29 00 } //1 unpaid evaluation copy of Resource Tuner 2 (www.heaventools.com)
		$a_01_1 = {75 74 69 6c 43 72 65 61 74 65 52 65 73 70 6f 6e 73 65 41 6e 64 42 79 70 61 73 73 53 65 72 76 65 72 } //2 utilCreateResponseAndBypassServer
		$a_01_2 = {53 74 65 61 6d 53 74 65 61 6c 65 72 } //3 SteamStealer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=6
 
}