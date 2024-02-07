
rule TrojanProxy_Win32_Dofoil_A{
	meta:
		description = "TrojanProxy:Win32/Dofoil.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 6d 6b 73 6f 63 6b 73 } //01 00  smksocks
		$a_00_1 = {3f 63 6d 64 3d 67 65 74 73 6f 63 6b 73 26 6c 6f 67 69 6e 3d } //01 00  ?cmd=getsocks&login=
		$a_01_2 = {8d 55 f0 8a 0a 33 db 8a d8 8d 3c 1e 33 db 8a d9 c1 eb 04 } //00 00 
	condition:
		any of ($a_*)
 
}