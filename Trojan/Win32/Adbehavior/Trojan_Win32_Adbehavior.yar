
rule Trojan_Win32_Adbehavior{
	meta:
		description = "Trojan:Win32/Adbehavior,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 0d 00 00 "
		
	strings :
		$a_00_0 = {64 6c 2e 77 65 62 2d 6e 65 78 75 73 2e 6e 65 74 } //3 dl.web-nexus.net
		$a_01_1 = {75 2e 61 64 2d 62 65 68 61 76 69 6f 72 2e 63 6f 6d } //3 u.ad-behavior.com
		$a_01_2 = {67 63 61 73 53 65 72 76 2e 65 78 65 00 00 } //3
		$a_01_3 = {4b 61 76 53 76 63 } //3 KavSvc
		$a_01_4 = {5c 51 6f 6f 6c 6f 67 69 63 5c 50 6f 70 75 70 43 6c 69 65 6e 74 5c 48 6f 6f 6b 53 72 76 5c 4d 79 44 65 62 75 67 5c 48 6f 6f 6b 53 72 76 } //2 \Qoologic\PopupClient\HookSrv\MyDebug\HookSrv
		$a_01_5 = {54 72 79 69 6e 67 20 62 69 67 20 70 6f 70 75 70 20 61 73 20 73 6d 61 6c 6c 20 70 6f 70 75 70 2e 2e } //2 Trying big popup as small popup..
		$a_01_6 = {6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 00 61 64 73 2e 62 69 64 63 6c 69 78 2e 63 6f 6d 00 6f 7a 2e 76 61 6c 75 65 63 6c 69 63 6b 2e 63 6f 6d } //2
		$a_01_7 = {6d 6d 61 70 5f 73 6e 69 70 69 6e 67 5f 72 75 6c 65 73 } //1 mmap_sniping_rules
		$a_01_8 = {73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 41 64 42 65 68 61 76 69 6f 72 } //1 sion\Uninstall\AdBehavior
		$a_01_9 = {79 6f 75 72 6b 65 79 00 6d 79 6b 65 79 } //1
		$a_01_10 = {63 6c 6b 6f 70 74 69 6d 69 7a 65 72 } //1 clkoptimizer
		$a_01_11 = {6d 79 6d 65 61 6e 6d 61 70 5f 00 61 72 6b 68 6d 6e 6a 70 75 6c } //1
		$a_01_12 = {67 74 61 73 6b 6d 67 72 2e 65 78 65 } //1 gtaskmgr.exe
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=7
 
}