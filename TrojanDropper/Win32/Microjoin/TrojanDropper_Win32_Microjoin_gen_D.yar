
rule TrojanDropper_Win32_Microjoin_gen_D{
	meta:
		description = "TrojanDropper:Win32/Microjoin.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 f4 01 00 00 90 90 90 02 04 55 8b 4b 1c 84 d2 74 90 01 01 90 02 04 d0 ea 72 90 01 01 90 02 04 d0 ea 72 90 01 01 90 02 04 d0 ea 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}