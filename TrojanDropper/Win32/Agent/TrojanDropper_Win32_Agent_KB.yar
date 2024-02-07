
rule TrojanDropper_Win32_Agent_KB{
	meta:
		description = "TrojanDropper:Win32/Agent.KB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {b0 6c 6a 47 68 90 01 03 00 c6 44 24 90 01 01 6b c6 44 24 90 01 01 72 c6 44 24 90 01 01 6e 90 00 } //01 00 
		$a_01_1 = {73 25 5c 73 65 63 69 76 72 65 53 5c 74 65 53 6c 6f 72 74 6e 6f 43 74 6e 65 72 72 75 43 5c 4d 45 54 53 59 53 } //01 00  s%\secivreS\teSlortnoCtnerruC\METSYS
		$a_00_2 = {00 30 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 00 } //01 00 
		$a_00_3 = {25 73 5c 25 64 5f 49 6e 64 65 78 2e 54 45 4d 50 } //01 00  %s\%d_Index.TEMP
		$a_00_4 = {4e 65 74 43 72 65 61 74 65 25 64 00 49 4d 47 53 56 43 } //00 00  敎䍴敲瑡╥d䵉升䍖
	condition:
		any of ($a_*)
 
}