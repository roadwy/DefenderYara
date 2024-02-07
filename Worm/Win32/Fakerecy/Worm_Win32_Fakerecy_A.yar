
rule Worm_Win32_Fakerecy_A{
	meta:
		description = "Worm:Win32/Fakerecy.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 20 56 69 73 75 61 6c 20 53 74 75 64 69 6f 5c 56 42 39 38 5c } //01 00  Microsoft Visual Studio\VB98\
		$a_01_1 = {5c 00 52 00 65 00 63 00 79 00 63 00 6c 00 65 00 64 00 5c 00 49 00 4e 00 46 00 4f 00 32 00 } //01 00  \Recycled\INFO2
		$a_01_2 = {5c 00 52 00 65 00 63 00 79 00 63 00 6c 00 65 00 64 00 5c 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 2e 00 69 00 6e 00 69 00 } //01 00  \Recycled\desktop.ini
		$a_01_3 = {5c 00 52 00 65 00 63 00 79 00 63 00 6c 00 65 00 64 00 5c 00 52 00 65 00 63 00 79 00 63 00 6c 00 65 00 64 00 5c 00 63 00 74 00 66 00 6d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //01 00  \Recycled\Recycled\ctfmon.exe
		$a_01_4 = {73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00 52 00 65 00 63 00 79 00 63 00 6c 00 65 00 64 00 5c 00 52 00 65 00 63 00 79 00 63 00 6c 00 65 00 64 00 5c 00 63 00 74 00 66 00 6d 00 6f 00 6e 00 2e 00 65 00 78 00 65 00 } //00 00  shellexecute=Recycled\Recycled\ctfmon.exe
	condition:
		any of ($a_*)
 
}