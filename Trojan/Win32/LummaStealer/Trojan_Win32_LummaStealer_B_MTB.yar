
rule Trojan_Win32_LummaStealer_B_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 8b 04 85 90 01 04 b9 90 01 04 33 0d 90 01 04 01 c8 40 90 00 } //01 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 20 31 30 } //01 00  Windows 10
		$a_01_2 = {57 69 6e 64 6f 77 73 20 31 31 } //00 00  Windows 11
	condition:
		any of ($a_*)
 
}