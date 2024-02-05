
rule DDoS_Win32_Dufeva_A{
	meta:
		description = "DDoS:Win32/Dufeva.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6c 64 64 6f 73 69 64 3d } //01 00 
		$a_03_1 = {b8 67 66 66 66 f7 e9 c1 fa 02 8b 90 01 01 c1 90 01 01 1f 03 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}