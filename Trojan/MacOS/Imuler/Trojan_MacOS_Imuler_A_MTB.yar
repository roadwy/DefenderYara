
rule Trojan_MacOS_Imuler_A_MTB{
	meta:
		description = "Trojan:MacOS/Imuler.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 6c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 63 68 65 63 6b 76 69 72 2e 70 6c 69 73 74 } //1 /library/LaunchAgents/checkvir.plist
		$a_00_1 = {2f 74 6d 70 2f 6c 61 75 6e 63 68 2d 30 72 70 2e 64 61 74 } //1 /tmp/launch-0rp.dat
		$a_00_2 = {2f 63 67 69 2d 6d 61 63 2f 32 77 6d 75 70 6c 6f 61 64 2e 63 67 69 } //1 /cgi-mac/2wmupload.cgi
		$a_00_3 = {2f 74 6d 70 2f 43 75 72 6c 55 70 6c 6f 61 64 20 2d 66 20 2f 74 6d 70 2f 78 6e 74 61 73 6b 7a } //1 /tmp/CurlUpload -f /tmp/xntaskz
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}