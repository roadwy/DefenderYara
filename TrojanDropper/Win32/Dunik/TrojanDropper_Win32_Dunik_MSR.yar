
rule TrojanDropper_Win32_Dunik_MSR{
	meta:
		description = "TrojanDropper:Win32/Dunik!MSR,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {52 75 6e 50 72 6f 67 72 61 6d 3d 22 68 69 64 63 6f 6e 3a 4f 38 37 34 31 34 2e 62 61 74 22 } //RunProgram="hidcon:O87414.bat"  01 00 
		$a_80_1 = {49 6e 73 74 61 6c 6c 50 61 74 68 3d 22 25 41 50 50 44 41 54 41 25 5c 4f 66 69 63 65 22 } //InstallPath="%APPDATA%\Ofice"  01 00 
		$a_80_2 = {3b 53 65 6c 66 44 65 6c 65 74 65 3d 22 31 22 } //;SelfDelete="1"  01 00 
		$a_80_3 = {4d 53 52 43 34 50 6c 75 67 69 6e 5f 66 6f 72 5f 73 63 2e 64 73 6d } //MSRC4Plugin_for_sc.dsm  01 00 
		$a_80_4 = {59 33 68 67 68 53 68 46 68 59 68 4e 68 47 68 6d 2e 69 6e 69 } //Y3hghShFhYhNhGhm.ini  01 00 
		$a_80_5 = {74 35 4d 43 4d 57 4d 6a 4d 36 4d 34 4d 52 4d 43 2e 70 6e 67 } //t5MCMWMjM6M4MRMC.png  01 00 
		$a_80_6 = {4e 68 6f 69 6f 61 6f 32 6f 69 6f 74 6f 48 6f 72 2e 70 6e 67 } //Nhoioao2oiotoHor.png  01 00 
		$a_80_7 = {72 63 34 2e 6b 65 79 } //rc4.key  00 00 
	condition:
		any of ($a_*)
 
}