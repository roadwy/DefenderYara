
rule Worm_Win32_Nohad_ON_MTB{
	meta:
		description = "Worm:Win32/Nohad.ON!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 6e 6f 64 34 32 2e 65 78 65 } //01 00  \nod42.exe
		$a_01_1 = {5c 6e 6f 74 74 65 70 61 64 2e 65 78 65 } //01 00  \nottepad.exe
		$a_01_2 = {6f 70 65 6e 3d 74 65 6d 70 5c 73 79 73 74 65 6d 2e 65 78 65 } //01 00  open=temp\system.exe
		$a_01_3 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 } //00 00  \Microsoft\Windows\Start Menu\Programs\Startup
	condition:
		any of ($a_*)
 
}