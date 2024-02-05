
rule Backdoor_Win32_Tnega_MA_MTB{
	meta:
		description = "Backdoor:Win32/Tnega.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 54 25 00 66 8b c4 d2 e8 81 c5 01 00 00 00 d2 d4 c1 f0 2e 32 d3 0f ab e0 d2 f8 80 ea cb d3 d8 9f 80 f2 5e 40 f6 da 0f 95 c4 80 ea 4f 66 2d 90 01 02 c0 cc 72 35 90 01 04 32 da 66 85 cf 88 0c 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}