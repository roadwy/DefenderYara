
rule Backdoor_BAT_DarkKomet_KA_MTB{
	meta:
		description = "Backdoor:BAT/DarkKomet.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 00 69 00 6e 00 64 00 65 00 64 00 2e 00 65 00 78 00 65 00 } //01 00  Binded.exe
		$a_01_1 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 } //01 00  C:\Users
		$a_01_2 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 57 00 69 00 6e 00 33 00 32 00 41 00 70 00 69 00 2e 00 65 00 78 00 65 00 } //01 00  \AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Win32Api.exe
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}