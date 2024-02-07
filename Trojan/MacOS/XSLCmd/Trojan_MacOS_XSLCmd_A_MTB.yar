
rule Trojan_MacOS_XSLCmd_A_MTB{
	meta:
		description = "Trojan:MacOS/XSLCmd.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 74 6d 70 2f 6f 73 6e 61 6d 65 2e 6c 6f 67 } //01 00  /tmp/osname.log
		$a_00_1 = {2f 74 6d 70 2f 6f 73 76 65 72 2e 6c 6f 67 } //01 00  /tmp/osver.log
		$a_00_2 = {73 63 72 65 65 6e 63 61 70 74 75 72 65 20 2d 6d 78 } //01 00  screencapture -mx
		$a_00_3 = {63 6f 6d 70 6f 73 65 2e 61 73 70 78 3f 73 3d 25 34 58 25 34 58 25 34 58 25 34 58 25 34 58 25 34 58 } //01 00  compose.aspx?s=%4X%4X%4X%4X%4X%4X
		$a_00_4 = {25 73 2f 25 30 34 64 25 30 32 64 25 30 32 64 5f 25 30 32 64 25 30 32 64 5f 25 30 32 64 5f 6b 65 79 73 2e 6c 6f 67 } //00 00  %s/%04d%02d%02d_%02d%02d_%02d_keys.log
		$a_00_5 = {5d 04 00 } //00 5c 
	condition:
		any of ($a_*)
 
}