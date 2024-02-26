
rule Trojan_Win32_LummaStealer_CCFX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 f7 fe 0f be 44 14 90 01 01 31 c1 0f be c1 8b 4c 24 90 01 01 8b 54 24 90 01 01 66 89 04 51 eb 90 00 } //01 00 
		$a_01_1 = {4c 75 6d 6d 61 43 32 } //01 00  LummaC2
		$a_01_2 = {6c 75 6d 6d 61 6e 6f 77 6f 72 6b } //00 00  lummanowork
	condition:
		any of ($a_*)
 
}