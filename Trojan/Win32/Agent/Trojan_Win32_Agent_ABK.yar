
rule Trojan_Win32_Agent_ABK{
	meta:
		description = "Trojan:Win32/Agent.ABK,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 69 78 66 69 6c 65 2e 65 78 65 } //01 00  fixfile.exe
		$a_01_1 = {41 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  Autorun.inf
		$a_01_2 = {3a 5c 41 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  :\Autorun.inf
		$a_01_3 = {5b 41 75 74 6f 52 75 6e 5d } //01 00  [AutoRun]
		$a_01_4 = {6f 70 65 6e 3d 52 65 63 79 63 31 65 64 5c 4d 63 73 68 69 65 31 64 2e 65 78 65 } //01 00  open=Recyc1ed\Mcshie1d.exe
		$a_01_5 = {73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 22 52 65 63 79 63 31 65 64 5c 4d 63 73 68 69 65 31 64 2e 65 78 65 } //01 00  shell\open\Command="Recyc1ed\Mcshie1d.exe
		$a_01_6 = {73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 43 6f 6d 6d 61 6e 64 3d 22 52 65 63 79 63 31 65 64 5c 4d 63 73 68 69 65 31 64 2e 65 78 65 20 2d 65 } //00 00  shell\explore\Command="Recyc1ed\Mcshie1d.exe -e
	condition:
		any of ($a_*)
 
}