
rule Worm_Win32_Phrositer{
	meta:
		description = "Worm:Win32/Phrositer,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1a 00 09 00 00 0b 00 "
		
	strings :
		$a_00_0 = {63 3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 6d 69 63 72 6f 73 6f 66 74 20 76 69 73 75 61 6c 20 73 74 75 64 69 6f 5c 76 62 39 38 5c 76 62 36 2e 6f 6c 62 } //0b 00  c:\program files\microsoft visual studio\vb98\vb6.olb
		$a_01_1 = {f5 00 00 00 00 05 06 00 3a 1c ff 49 00 fb ef 6c ff 0a 10 00 08 00 fd 6b fc fe fc f6 0c ff 35 6c ff 00 16 } //02 00 
		$a_01_2 = {53 65 70 68 69 72 6f 74 } //01 00  Sephirot
		$a_01_3 = {72 65 67 61 74 74 61 63 6b } //01 00  regattack
		$a_01_4 = {69 6e 66 65 63 74 64 72 69 76 65 } //01 00  infectdrive
		$a_80_5 = {67 3a 5c 6b 61 64 61 6a 2e 65 78 65 } //g:\kadaj.exe  02 00 
		$a_80_6 = {73 68 65 6c 6c 5c 41 75 74 6f 5c 63 6f 6d 6d 61 6e 64 3d 6b 61 64 61 6a 2e 65 78 65 } //shell\Auto\command=kadaj.exe  02 00 
		$a_80_7 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 72 6f 6e 69 6e 20 2f 61 64 64 } //net localgroup administrators ronin /add  01 00 
		$a_80_8 = {53 6d 69 6c 65 2c 20 44 6f 6f 7a 6f 20 59 6f 72 6f 73 68 69 6b 75 } //Smile, Doozo Yoroshiku  00 00 
	condition:
		any of ($a_*)
 
}