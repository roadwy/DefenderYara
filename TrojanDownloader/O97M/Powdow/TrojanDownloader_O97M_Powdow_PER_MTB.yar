
rule TrojanDownloader_O97M_Powdow_PER_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PER!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 25 5e 74 25 5e 74 25 5e 70 25 5e 3a 25 5e 2f 25 5e 2f 25 5e 6c 25 5e 69 25 5e 6d 25 5e 69 25 5e 74 25 5e 65 25 5e 64 25 5e 65 25 5e 64 25 5e 69 25 5e 74 25 5e 69 25 5e 6f 25 5e 6e 25 5e 70 25 5e 68 25 5e 6f 25 5e 74 25 5e 6f 25 5e 73 25 5e 2e 25 5e 6e 25 5e 6c 25 5e 2f 25 5e 77 25 5e 70 25 5e 2d 25 5e 69 25 5e 6e 25 5e 63 25 5e 6c 25 5e 75 25 5e 64 25 5e 65 25 5e 73 25 5e 2f 25 5e 49 25 5e 44 25 5e 33 25 5e 2f 25 5e 7a 25 5e 7a 25 5e 7a 25 5e 2e 25 5e 74 25 5e 78 25 5e 74 25 5e } //01 00  h%^t%^t%^p%^:%^/%^/%^l%^i%^m%^i%^t%^e%^d%^e%^d%^i%^t%^i%^o%^n%^p%^h%^o%^t%^o%^s%^.%^n%^l%^/%^w%^p%^-%^i%^n%^c%^l%^u%^d%^e%^s%^/%^I%^D%^3%^/%^z%^z%^z%^.%^t%^x%^t%^
		$a_01_1 = {74 74 20 3d 20 52 65 70 6c 61 63 65 28 74 74 2c 20 22 25 5e 22 2c 20 22 22 29 } //01 00  tt = Replace(tt, "%^", "")
		$a_01_2 = {63 63 20 3d 20 53 74 72 69 6e 67 28 31 2c 20 22 50 7e 57 51 37 38 37 48 31 4a 4d 58 59 48 5a 37 46 53 31 47 31 33 4a 30 54 4d 51 36 58 52 34 5a 22 29 } //01 00  cc = String(1, "P~WQ787H1JMXYHZ7FS1G13J0TMQ6XR4Z")
		$a_01_3 = {53 68 65 6c 6c 4f 62 6a 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 63 63 2c 20 74 74 } //00 00  ShellObj.ShellExecute cc, tt
	condition:
		any of ($a_*)
 
}