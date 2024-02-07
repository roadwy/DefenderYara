
rule TrojanDropper_Win32_Bifrose_F{
	meta:
		description = "TrojanDropper:Win32/Bifrose.F,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {5c 00 42 00 69 00 66 00 72 00 6f 00 73 00 74 00 20 00 53 00 74 00 75 00 62 00 20 00 47 00 65 00 6e 00 65 00 72 00 61 00 74 00 6f 00 72 00 20 00 76 00 } //02 00  \Bifrost Stub Generator v
		$a_01_1 = {43 30 6e 76 33 52 74 } //00 00  C0nv3Rt
	condition:
		any of ($a_*)
 
}