
rule Trojan_Win32_NSISInjector_EM_MTB{
	meta:
		description = "Trojan:Win32/NSISInjector.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 63 6f 6e 6e 65 63 74 69 6f 6e } //01 00  Interconnection
		$a_01_1 = {53 76 65 64 64 72 69 76 65 6e 64 65 } //01 00  Sveddrivende
		$a_01_2 = {47 6f 6e 79 6f 63 65 6c 65 } //01 00  Gonyocele
		$a_01_3 = {52 00 61 00 6e 00 63 00 68 00 6c 00 65 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  Ranchless.exe
		$a_01_4 = {47 65 74 53 68 6f 72 74 50 61 74 68 4e 61 6d 65 41 } //01 00  GetShortPathNameA
		$a_01_5 = {43 72 65 61 74 65 46 69 6c 65 41 } //00 00  CreateFileA
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_NSISInjector_EM_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInjector.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 48 00 55 00 44 00 45 00 5c 00 53 00 75 00 6c 00 70 00 68 00 6f 00 63 00 79 00 61 00 6e 00 61 00 74 00 65 00 2e 00 4b 00 6f 00 6c 00 } //01 00  CHUDE\Sulphocyanate.Kol
		$a_01_1 = {42 00 72 00 6f 00 77 00 6e 00 2d 00 46 00 6f 00 72 00 6d 00 61 00 6e 00 } //01 00  Brown-Forman
		$a_01_2 = {50 00 69 00 74 00 74 00 73 00 74 00 6f 00 6e 00 20 00 42 00 72 00 69 00 6e 00 6b 00 73 00 } //01 00  Pittston Brinks
		$a_01_3 = {58 00 70 00 6c 00 6f 00 64 00 65 00 } //01 00  Xplode
		$a_01_4 = {4e 00 61 00 6e 00 6f 00 73 00 79 00 73 00 74 00 65 00 6d 00 73 00 } //00 00  Nanosystems
	condition:
		any of ($a_*)
 
}