
rule Trojan_Win32_DCRat_B_MTB{
	meta:
		description = "Trojan:Win32/DCRat.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 45 78 63 6c 75 73 69 6f 6e 73 } //02 00  SOFTWARE\Microsoft\Windows Defender\Exclusions
		$a_01_1 = {45 78 63 6c 75 73 69 6f 6e 50 72 6f 63 65 73 73 } //02 00  ExclusionProcess
		$a_01_2 = {63 6e 35 2b 65 6b 51 35 4f 54 74 44 50 54 67 38 50 54 30 34 50 6b 4d 34 50 44 70 44 4f 51 3d 3d } //02 00  cn5+ekQ5OTtDPTg8PT04PkM4PDpDOQ==
		$a_01_3 = {76 6d 73 72 76 63 2e 73 79 73 } //00 00  vmsrvc.sys
	condition:
		any of ($a_*)
 
}