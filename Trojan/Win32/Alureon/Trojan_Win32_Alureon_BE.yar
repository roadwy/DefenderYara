
rule Trojan_Win32_Alureon_BE{
	meta:
		description = "Trojan:Win32/Alureon.BE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 10 8a d1 02 54 24 08 30 14 01 41 3b 4c 24 04 72 f0 } //01 00 
		$a_03_1 = {f3 a6 74 10 8b f0 6a 0a bf 90 01 04 59 33 c0 f3 a6 90 00 } //01 00 
		$a_01_2 = {74 64 6c 6c 6f 67 2e 64 6c 6c } //00 00  tdllog.dll
	condition:
		any of ($a_*)
 
}