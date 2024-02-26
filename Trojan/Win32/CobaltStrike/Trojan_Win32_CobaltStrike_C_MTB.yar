
rule Trojan_Win32_CobaltStrike_C_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {6b 72 70 74 5f 52 65 67 69 73 74 65 72 57 45 52 48 61 6e 64 6c 65 72 } //02 00  krpt_RegisterWERHandler
		$a_01_1 = {6b 72 70 74 5f 52 65 6d 6f 76 65 44 6c 6c 46 69 6c 74 65 72 50 72 6f 74 65 63 74 44 65 74 6f 75 72 } //02 00  krpt_RemoveDllFilterProtectDetour
		$a_01_2 = {6b 72 70 74 5f 52 65 6d 6f 76 65 52 75 6e 74 69 6d 65 50 72 6f 74 65 63 74 44 65 74 6f 75 72 } //02 00  krpt_RemoveRuntimeProtectDetour
		$a_01_3 = {6b 72 70 74 5f 52 75 6e 74 69 6d 65 50 72 6f 74 65 63 74 } //02 00  krpt_RuntimeProtect
		$a_01_4 = {5f 66 6f 72 63 65 5f 6c 69 6e 6b 5f 6b 72 70 74 } //02 00  _force_link_krpt
		$a_01_5 = {72 75 6e 64 6c 6c 33 32 } //00 00  rundll32
	condition:
		any of ($a_*)
 
}