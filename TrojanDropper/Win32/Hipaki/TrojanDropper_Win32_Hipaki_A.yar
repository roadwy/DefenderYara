
rule TrojanDropper_Win32_Hipaki_A{
	meta:
		description = "TrojanDropper:Win32/Hipaki.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 2f 45 80 37 1b 80 37 45 f6 17 47 e2 f2 } //01 00 
		$a_03_1 = {68 00 00 00 80 86 db 68 90 01 04 86 db 68 90 01 04 86 db 50 86 db c3 86 db a3 90 01 04 86 db 83 f8 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}