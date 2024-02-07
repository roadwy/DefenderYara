
rule Worm_Win32_Autorun_QU{
	meta:
		description = "Worm:Win32/Autorun.QU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8d 45 98 50 ff 15 90 01 04 50 e8 90 01 04 89 85 80 fe ff ff ff 15 90 01 04 33 c9 83 bd 80 fe ff ff 02 0f 94 c1 f7 d9 90 00 } //01 00 
		$a_01_1 = {5b 00 41 00 75 00 74 00 6f 00 52 00 75 00 6e 00 5d 00 } //01 00  [AutoRun]
		$a_01_2 = {73 00 68 00 65 00 6c 00 6c 00 5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 5c 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 27 00 27 00 } //01 00  shell\explore\Command=''
		$a_01_3 = {53 00 56 00 43 00 48 00 30 00 53 00 54 00 2e 00 45 00 58 00 45 00 } //00 00  SVCH0ST.EXE
	condition:
		any of ($a_*)
 
}