
rule Backdoor_MacOS_Muxler_A_MTB{
	meta:
		description = "Backdoor:MacOS/Muxler.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 61 63 20 73 72 63 2f 6d 61 63 20 74 72 6f 6a 61 6e 20 2f 7a 6c 69 62 2f } //1 mac src/mac trojan /zlib/
		$a_00_1 = {2f 6c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 63 68 65 63 6b 76 69 72 2e 70 6c 69 73 74 } //1 /library/LaunchAgents/checkvir.plist
		$a_00_2 = {62 6f 73 74 61 6e 6c 69 6b 2e 63 6f 6d 2f 63 67 69 2d 6d 61 63 2f 77 6d 63 68 65 63 6b 64 69 72 2e 63 67 69 } //1 bostanlik.com/cgi-mac/wmcheckdir.cgi
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}