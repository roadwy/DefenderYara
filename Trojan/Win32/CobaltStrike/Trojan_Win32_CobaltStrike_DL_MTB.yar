
rule Trojan_Win32_CobaltStrike_DL_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff d1 50 8b 85 50 f8 ff ff c7 04 24 00 00 00 00 ff d0 50 a1 78 71 b8 6b 89 85 44 f8 ff ff c7 04 24 00 00 00 00 ff d0 } //01 00 
		$a_01_1 = {71 75 69 6f 6d 6e 69 73 73 69 74 61 6c 69 71 75 69 64 6d 6f 6c 65 73 74 69 61 73 32 34 2e 64 6c 6c } //00 00  quiomnissitaliquidmolestias24.dll
	condition:
		any of ($a_*)
 
}