
rule HackTool_Win32_DarkComet{
	meta:
		description = "HackTool:Win32/DarkComet,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {44 61 72 6b 43 6f 6d 65 74 90 01 01 52 41 54 20 2d 20 4e 65 77 20 55 73 65 72 20 21 90 00 } //01 00 
		$a_01_1 = {2d 44 61 72 6b 43 6f 6d 65 74 2d 52 41 54 20 57 65 62 20 53 69 74 65 20 61 6e 64 20 53 6f 66 74 77 61 72 65 20 41 67 72 65 65 6d 65 6e 74 } //01 00  -DarkComet-RAT Web Site and Software Agreement
		$a_01_2 = {44 61 72 6b 43 6f 6d 65 74 20 69 73 20 73 79 6e 63 68 72 6f 6e 69 7a 65 64 20 77 69 74 68 20 6e 6f 2d 69 70 20 64 6e 73 20 73 65 72 76 69 63 65 } //01 00  DarkComet is synchronized with no-ip dns service
		$a_01_3 = {41 41 63 74 69 76 65 20 64 61 72 6b 63 6f 6d 65 74 20 73 6b 69 6e 20 66 6f 72 6d 20 73 79 73 74 65 6d } //01 00  AActive darkcomet skin form system
		$a_01_4 = {44 00 61 00 72 00 6b 00 43 00 6f 00 6d 00 65 00 74 00 20 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 54 00 6f 00 6f 00 6c 00 } //01 00  DarkComet Remote Administration Tool
		$a_01_5 = {44 00 61 00 72 00 6b 00 43 00 6f 00 6d 00 65 00 74 00 20 00 61 00 6b 00 61 00 20 00 55 00 6e 00 72 00 65 00 6d 00 6f 00 74 00 65 00 20 00 4e 00 41 00 54 00 20 00 61 00 6b 00 61 00 20 00 53 00 79 00 6e 00 52 00 41 00 54 00 } //00 00  DarkComet aka Unremote NAT aka SynRAT
	condition:
		any of ($a_*)
 
}