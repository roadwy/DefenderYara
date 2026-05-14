
rule Trojan_Win32_SysWiper_GA_MTB{
	meta:
		description = "Trojan:Win32/SysWiper.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 77 69 70 65 5f 73 65 72 76 65 72 } //1 main.wipe_server
		$a_01_1 = {6d 61 69 6e 2e 73 72 76 5f 68 61 6e 64 6c 65 72 } //1 main.srv_handler
		$a_01_2 = {67 6f 3a 74 65 78 74 66 69 70 73 73 74 61 72 74 } //1 go:textfipsstart
		$a_01_3 = {57 69 70 69 6e 67 20 73 65 72 76 65 72 2e 2e } //1 Wiping server..
		$a_01_4 = {77 69 70 65 2e 53 74 6f 70 53 65 72 76 65 72 } //1 wipe.StopServer
		$a_01_5 = {77 69 70 65 2e 4b 69 6c 6c 53 65 72 76 65 72 } //1 wipe.KillServer
		$a_01_6 = {77 69 70 65 2e 53 74 61 72 74 53 65 72 76 65 72 } //1 wipe.StartServer
		$a_01_7 = {50 72 69 6e 74 20 6f 75 74 20 63 6f 6e 66 69 67 20 61 6e 64 20 65 78 69 74 } //1 Print out config and exit
		$a_01_8 = {50 72 69 6e 74 20 6f 75 74 20 76 65 72 73 69 6f 6e 20 61 6e 64 20 65 78 69 74 } //1 Print out version and exit
		$a_01_9 = {54 68 65 20 70 61 74 68 20 74 6f 20 74 68 65 20 52 75 73 74 20 41 75 74 6f 20 57 69 70 65 20 63 6f 6e 66 69 67 20 66 69 6c 65 2e } //1 The path to the Rust Auto Wipe config file.
		$a_01_10 = {2d 63 66 67 3d 20 2d 2d 63 66 67 20 2d 63 66 67 20 3c 70 61 74 68 3e 20 3e 20 50 61 74 68 20 74 6f 20 63 6f 6e 66 69 67 20 66 69 6c 65 20 6f 76 65 72 72 69 64 65 2e } //1 -cfg= --cfg -cfg <path> > Path to config file override.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}