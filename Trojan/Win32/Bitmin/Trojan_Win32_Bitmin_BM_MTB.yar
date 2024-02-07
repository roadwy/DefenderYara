
rule Trojan_Win32_Bitmin_BM_MTB{
	meta:
		description = "Trojan:Win32/Bitmin.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {72 65 6e 69 6d 75 73 65 2e 6f 63 72 79 2e 63 6f 6d 2f 72 65 6e 69 6d 36 34 2e 65 78 65 } //02 00  renimuse.ocry.com/renim64.exe
		$a_01_1 = {73 74 61 72 74 20 69 6e 74 65 6c 75 73 72 2e 65 78 65 } //02 00  start intelusr.exe
		$a_01_2 = {72 65 6e 69 6d 75 73 65 2e 6f 63 72 79 2e 63 6f 6d 2f 72 65 6e 69 6d 33 32 2e 65 78 65 } //01 00  renimuse.ocry.com/renim32.exe
		$a_01_3 = {70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 38 } //00 00  ping 127.0.0.1 -n 8
	condition:
		any of ($a_*)
 
}