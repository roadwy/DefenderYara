
rule PWS_Win32_Wowsteal_AY{
	meta:
		description = "PWS:Win32/Wowsteal.AY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 81 7d ?? e8 43 05 00 0f 94 c0 } //1
		$a_03_1 = {6a 40 6a 05 68 ?? ?? 04 00 ff 75 ?? c6 45 ?? 67 c6 45 ?? e4 } //1
		$a_03_2 = {6a 05 50 68 ?? ?? 40 00 ff 75 08 ff ?? 8d 45 ?? c6 45 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}