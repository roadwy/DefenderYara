
rule Trojan_MacOS_Xcsset_A_xp{
	meta:
		description = "Trojan:MacOS/Xcsset.A!xp,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {73 65 63 75 72 69 74 79 2e 63 73 70 2e 65 6e 61 62 6c 65 90 02 03 66 61 6c 73 65 90 00 } //1
		$a_01_1 = {75 73 65 72 5f 70 72 65 66 28 22 64 65 76 74 6f 6f 6c 73 2e 64 65 62 75 67 67 65 72 2e 72 65 6d 6f 74 65 2d 65 6e 61 62 6c 65 64 } //1 user_pref("devtools.debugger.remote-enabled
		$a_01_2 = {6b 69 6c 6c 61 6c 6c 20 2d 39 20 27 66 69 72 65 66 6f 78 27 20 32 3e 20 2f 64 65 76 2f 6e 75 6c 6c } //1 killall -9 'firefox' 2> /dev/null
		$a_01_3 = {2f 61 70 70 6c 65 2f 61 67 65 6e 74 64 2e 70 68 70 } //1 /apple/agentd.php
		$a_00_4 = {45 78 65 63 75 74 65 64 20 70 61 79 70 61 6c 20 70 61 79 6c 6f 61 64 73 } //1 Executed paypal payloads
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}