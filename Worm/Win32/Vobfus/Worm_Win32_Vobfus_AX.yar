
rule Worm_Win32_Vobfus_AX{
	meta:
		description = "Worm:Win32/Vobfus.AX,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 54 ff 67 00 fd f0 08 00 20 00 00 89 94 08 00 c8 01 1b 16 00 2a 23 30 ff 1b 14 00 2a 23 24 ff 1b 12 00 2a 23 20 ff 1b 72 00 2a 23 1c ff 1b 73 00 2a 23 18 ff 1b 74 00 2a 23 14 ff 1b 71 00 2a 23 10 ff 1b 75 00 2a 23 0c ff 1b 76 00 } //00 00 
	condition:
		any of ($a_*)
 
}