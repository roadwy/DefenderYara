
rule Trojan_Win32_Emotet_PSL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 10 88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 85 90 01 04 8a 94 15 90 01 04 30 10 90 00 } //01 00 
		$a_81_1 = {62 68 75 78 43 2a 37 64 6c 44 49 57 4d 5e 6a 6f 55 35 4d 36 6d 34 76 72 58 73 7a 72 62 70 32 4a 32 4e 4b 37 } //00 00  bhuxC*7dlDIWM^joU5M6m4vrXszrbp2J2NK7
	condition:
		any of ($a_*)
 
}