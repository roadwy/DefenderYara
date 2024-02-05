
rule HackTool_Win32_LaZagne{
	meta:
		description = "HackTool:Win32/LaZagne,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 10 00 00 ffffffec ffffffff "
		
	strings :
		$a_80_0 = {4d 69 63 72 6f 73 6f 66 74 2e 43 79 62 65 72 2e 4f 62 73 65 72 76 61 74 69 6f 6e 44 65 74 65 63 74 6f 72 73 2e 64 6c 6c } //Microsoft.Cyber.ObservationDetectors.dll  ec ff 
		$a_80_1 = {4f 6e 65 43 79 62 65 72 46 54 40 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //OneCyberFT@microsoft.com  06 00 
		$a_80_2 = {6c 61 5a 61 67 6e 65 2e 65 78 65 2e 6d 61 6e 69 66 65 73 74 } //laZagne.exe.manifest  03 00 
		$a_80_3 = {6c 61 7a 61 67 6e 65 2e 63 6f 6e 66 69 67 } //lazagne.config  03 00 
		$a_80_4 = {6c 61 7a 61 67 6e 65 2e 73 6f 66 74 77 61 72 65 73 } //lazagne.softwares  03 00 
		$a_80_5 = {6d 69 6d 69 6b 61 74 7a } //mimikatz  02 00 
		$a_80_6 = {6c 61 7a 61 67 6e 65 } //lazagne  03 00 
		$a_80_7 = {20 6e 61 6d 65 3d 22 6c 61 5a 61 67 6e 65 31 22 20 } // name="laZagne1"   02 00 
		$a_80_8 = {2e 6c 73 61 5f 73 65 63 72 65 74 73 } //.lsa_secrets  02 00 
		$a_80_9 = {2e 77 69 6e 64 6f 77 73 2e 73 65 63 72 65 74 73 64 75 6d 70 } //.windows.secretsdump  02 00 
		$a_80_10 = {2e 77 69 66 69 2e 77 69 66 69 70 61 73 73 } //.wifi.wifipass  01 00 
		$a_80_11 = {2e 62 72 6f 77 73 65 72 73 2e 69 65 } //.browsers.ie  01 00 
		$a_80_12 = {2e 63 68 61 74 73 2e 6a 69 74 73 69 } //.chats.jitsi  01 00 
		$a_80_13 = {2e 67 61 6d 65 73 2e 6b 61 6c 79 70 73 6f 6d 65 64 69 61 } //.games.kalypsomedia  01 00 
		$a_80_14 = {2e 67 69 74 2e 67 69 74 66 6f 72 77 69 6e 64 6f 77 73 } //.git.gitforwindows  01 00 
		$a_80_15 = {2e 73 79 73 61 64 6d 69 6e 2e 61 70 61 63 68 65 64 69 72 65 63 74 6f 72 79 73 74 75 64 69 6f } //.sysadmin.apachedirectorystudio  00 00 
		$a_00_16 = {5d 04 00 00 0c af } //03 80 
	condition:
		any of ($a_*)
 
}