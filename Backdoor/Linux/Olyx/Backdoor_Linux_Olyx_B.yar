
rule Backdoor_Linux_Olyx_B{
	meta:
		description = "Backdoor:Linux/Olyx.B,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 6b 65 79 3e 52 75 6e 41 74 4c 6f 61 64 3c 2f 6b 65 79 3e } //01 00  <key>RunAtLoad</key>
		$a_01_1 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f } //03 00  /Library/LaunchAgents/
		$a_01_2 = {2f 4c 69 62 72 61 72 79 2f 41 75 64 69 6f 2f 50 6c 75 67 2d 49 6e 73 2f 41 75 64 69 6f 53 65 72 76 65 72 } //03 00  /Library/Audio/Plug-Ins/AudioServer
		$a_01_3 = {64 6e 73 2e 61 73 73 79 72 61 2e 63 6f 6d } //03 00  dns.assyra.com
		$a_01_4 = {30 04 0a 48 ff c2 48 83 fa 10 75 ec 0f b6 01 c1 e0 08 } //03 00 
		$a_01_5 = {0f b6 82 14 02 00 00 32 01 88 82 14 02 00 00 0f b6 82 54 02 00 00 32 01 88 82 54 02 00 00 42 41 39 f1 } //02 00 
		$a_03_6 = {ba 00 00 00 00 83 f8 01 75 90 02 06 00 00 c7 00 fa ff ff ff ba 01 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}