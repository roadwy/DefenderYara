
rule Trojan_Win32_Swrort_C{
	meta:
		description = "Trojan:Win32/Swrort.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5e 56 31 1e ad 01 c3 85 c0 75 f7 } //01 00 
		$a_03_1 = {e8 ff ff ff ff c0 5e 81 76 0e 90 01 04 83 ee fc e2 f4 90 00 } //9c ff 
		$a_00_2 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 53 00 79 00 6d 00 61 00 6e 00 74 00 65 00 63 00 5c 00 53 00 79 00 6d 00 61 00 6e 00 74 00 65 00 63 00 20 00 45 00 6e 00 64 00 70 00 6f 00 69 00 6e 00 74 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 5c 00 31 00 32 00 2e 00 31 00 2e 00 37 00 30 00 30 00 34 00 2e 00 36 00 35 00 30 00 30 00 2e 00 31 00 30 00 35 00 5c 00 44 00 61 00 74 00 61 00 } //00 00  C:\ProgramData\Symantec\Symantec Endpoint Protection\12.1.7004.6500.105\Data
	condition:
		any of ($a_*)
 
}