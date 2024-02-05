
rule Trojan_Win32_Dridex_AR_MSR{
	meta:
		description = "Trojan:Win32/Dridex.AR!MSR,SIGNATURE_TYPE_PEHSTR,05 00 05 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {5c 6d 61 64 65 5c 4e 61 6d 65 5c 6f 68 5c 67 65 6e 74 6c 65 5c 53 6f 6c 75 74 69 6f 6e 5f 6f 6e 65 5c 75 73 65 2e 70 64 62 } //05 00 
		$a_01_1 = {5c 43 68 6f 72 64 2d 66 65 6c 74 5c 36 36 38 5c 57 72 6f 6e 67 5c 37 36 37 5c 53 6f 6c 64 69 65 72 2d 73 74 72 65 61 6d 5c 47 6f 6f 64 2e 70 64 62 } //05 00 
		$a_01_2 = {5c 53 65 61 73 6f 6e 5c 57 69 66 65 5f 6c 6f 77 5c 35 33 31 5c 51 75 61 72 74 5c 74 61 62 6c 65 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}