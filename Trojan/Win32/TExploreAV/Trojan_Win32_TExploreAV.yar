
rule Trojan_Win32_TExploreAV{
	meta:
		description = "Trojan:Win32/TExploreAV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 45 78 70 6c 6f 72 65 20 41 56 20 53 45 54 55 50 00 } //01 00  䕔灸潬敲䄠⁖䕓啔P
		$a_01_1 = {45 78 74 72 6f 79 61 6e 2e 45 58 5f 00 } //01 00 
		$a_01_2 = {49 4e 44 49 43 45 2e 44 4f 5f 00 } //01 00 
		$a_01_3 = {55 52 4c 2e 55 52 5f 00 fd 9f 80 00 4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TExploreAV_2{
	meta:
		description = "Trojan:Win32/TExploreAV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 00 77 00 77 00 2e 00 74 00 72 00 6f 00 79 00 61 00 6e 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 61 00 72 00 } //01 00  www.troyanexplore.com.ar
		$a_01_1 = {54 00 4d 00 52 00 20 00 28 00 54 00 72 00 61 00 74 00 61 00 6d 00 69 00 65 00 6e 00 74 00 6f 00 20 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 20 00 52 00 65 00 73 00 69 00 64 00 65 00 6e 00 74 00 65 00 29 00 } //01 00  TMR (Tratamiento Malware Residente)
		$a_01_2 = {66 00 75 00 6c 00 6c 00 20 00 2f 00 20 00 43 00 6c 00 65 00 61 00 6e 00 2d 00 75 00 70 00 20 00 6f 00 6e 00 20 00 66 00 75 00 6c 00 6c 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 } //01 00  full / Clean-up on full version
		$a_01_3 = {3e 00 44 00 75 00 64 00 6f 00 73 00 6f 00 73 00 2f 00 53 00 75 00 73 00 70 00 65 00 63 00 74 00 73 00 } //00 00  >Dudosos/Suspects
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TExploreAV_3{
	meta:
		description = "Trojan:Win32/TExploreAV,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 00 72 00 6f 00 79 00 61 00 6e 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 61 00 72 00 2e 00 55 00 52 00 4c 00 } //01 00  Troyanexplore.com.ar.URL
		$a_01_1 = {52 00 65 00 61 00 6c 00 2d 00 54 00 69 00 6d 00 65 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 5c 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 4f 00 6e 00 41 00 63 00 63 00 65 00 73 00 73 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 } //01 00  Real-Time Protection\DisableOnAccessProtection
		$a_01_2 = {54 00 72 00 6f 00 79 00 61 00 6e 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 5c 00 49 00 6e 00 73 00 74 00 61 00 6c 00 61 00 72 00 2e 00 76 00 62 00 70 00 } //01 00  TroyanExplore\Instalar.vbp
		$a_01_3 = {49 00 6e 00 73 00 74 00 61 00 6c 00 61 00 64 00 6f 00 72 00 20 00 54 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 } //00 00  Instalador TExplore Antivirus
	condition:
		any of ($a_*)
 
}