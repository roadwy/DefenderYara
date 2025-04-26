
rule HackTool_BAT_HotBrute_A{
	meta:
		description = "HackTool:BAT/HotBrute.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6e 42 72 75 74 65 5f 46 6f 72 63 65 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 nBrute_Force.My.Resources
		$a_01_1 = {6e 00 42 00 72 00 75 00 74 00 65 00 20 00 46 00 6f 00 72 00 63 00 65 00 20 00 76 00 } //1 nBrute Force v
		$a_01_2 = {43 00 6f 00 64 00 65 00 64 00 20 00 42 00 79 00 3a 00 20 00 6e 00 6a 00 71 00 38 00 20 00 45 00 6d 00 61 00 69 00 6c 00 3a 00 20 00 6e 00 6a 00 71 00 38 00 40 00 79 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 Coded By: njq8 Email: njq8@ymail.com
		$a_01_3 = {70 00 6f 00 70 00 33 00 2e 00 6c 00 69 00 76 00 65 00 2e 00 63 00 6f 00 6d 00 } //1 pop3.live.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}