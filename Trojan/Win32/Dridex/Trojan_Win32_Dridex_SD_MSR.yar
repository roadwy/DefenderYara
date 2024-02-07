
rule Trojan_Win32_Dridex_SD_MSR{
	meta:
		description = "Trojan:Win32/Dridex.SD!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 64 65 61 72 5c 64 61 6e 67 65 72 52 61 69 6e 5c 73 69 6e 63 65 53 75 67 61 72 5c 43 65 6e 74 65 72 73 75 62 74 72 61 63 74 5c 50 61 74 68 57 65 6c 6c 5c 4d 61 74 65 72 69 61 6c 4e 61 6d 65 5c 61 6c 6c 74 61 6c 6c 68 69 73 2e 70 64 62 } //01 00  powerdear\dangerRain\sinceSugar\Centersubtract\PathWell\MaterialName\alltallhis.pdb
		$a_01_1 = {4c 6f 63 6b 57 69 6e 64 6f 77 55 70 64 61 74 65 } //01 00  LockWindowUpdate
		$a_01_2 = {4c 6f 63 6b 46 69 6c 65 } //01 00  LockFile
		$a_01_3 = {4c 6f 63 6b 52 65 73 6f 75 72 63 65 } //01 00  LockResource
		$a_01_4 = {50 00 61 00 73 00 73 00 20 00 42 00 65 00 6c 00 6c 00 65 00 76 00 65 00 72 00 79 00 } //00 00  Pass Bellevery
	condition:
		any of ($a_*)
 
}