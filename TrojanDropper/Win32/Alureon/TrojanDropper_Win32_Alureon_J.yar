
rule TrojanDropper_Win32_Alureon_J{
	meta:
		description = "TrojanDropper:Win32/Alureon.J,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_03_0 = {8a d1 80 c2 ?? 30 14 90 04 01 04 01 19 31 39 83 c1 01 3b 90 04 01 04 c8 cb ce cf 72 f1 c3 } //10
		$a_00_1 = {74 64 73 73 44 61 74 61 } //1 tdssData
		$a_00_2 = {74 64 73 73 61 64 77 2e 64 6c 6c } //1 tdssadw.dll
		$a_00_3 = {5c 74 64 73 73 69 6e 69 74 2e 64 6c 6c } //1 \tdssinit.dll
		$a_00_4 = {74 00 64 00 73 00 73 00 68 00 65 00 6c 00 70 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 } //1 tdsshelper.dll
		$a_00_5 = {5c 00 64 00 65 00 76 00 69 00 63 00 65 00 5c 00 6e 00 61 00 6d 00 65 00 64 00 70 00 69 00 70 00 65 00 5c 00 74 00 64 00 6c 00 63 00 6d 00 64 00 } //1 \device\namedpipe\tdlcmd
		$a_02_6 = {61 64 77 5f 64 6c 6c [0-01] 2e 64 6c 6c 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1) >=12
 
}