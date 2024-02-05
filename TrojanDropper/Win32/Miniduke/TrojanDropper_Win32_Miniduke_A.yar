
rule TrojanDropper_Win32_Miniduke_A{
	meta:
		description = "TrojanDropper:Win32/Miniduke.A,SIGNATURE_TYPE_PEHSTR,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 41 53 4b 4b 49 4c 4c 20 2f 46 20 2f 49 4d 20 61 63 72 6f 2a } //00 00 
	condition:
		any of ($a_*)
 
}