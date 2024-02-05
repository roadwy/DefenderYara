
rule Worm_Win32_Palevo{
	meta:
		description = "Worm:Win32/Palevo,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 52 45 44 4f 0a 64 65 6c 20 25 30 0a 65 78 69 74 } //01 00 
		$a_01_1 = {2f 6c 64 72 2f 63 6c 69 65 6e 74 2e 70 68 70 3f 66 61 6d 69 6c 79 3d 62 61 6e 6b } //00 00 
	condition:
		any of ($a_*)
 
}