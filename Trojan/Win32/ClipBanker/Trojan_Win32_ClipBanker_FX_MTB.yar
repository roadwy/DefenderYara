
rule Trojan_Win32_ClipBanker_FX_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.FX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {48 89 d0 48 01 c0 48 01 d0 48 c1 e0 03 48 8d 8d 90 01 04 48 01 c8 48 2d a0 01 00 00 48 8b 00 90 00 } //0a 00 
		$a_01_1 = {48 89 05 65 6b 00 00 48 8b 05 5e 25 00 00 48 89 45 f0 48 8b 05 63 25 00 00 48 89 45 f8 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_3 = {47 65 74 43 6c 69 70 62 6f 61 72 64 44 61 74 61 } //00 00  GetClipboardData
	condition:
		any of ($a_*)
 
}