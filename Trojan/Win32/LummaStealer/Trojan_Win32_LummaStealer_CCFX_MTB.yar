
rule Trojan_Win32_LummaStealer_CCFX_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.CCFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {99 f7 fe 0f be 44 14 ?? 31 c1 0f be c1 8b 4c 24 ?? 8b 54 24 ?? 66 89 04 51 eb } //1
		$a_01_1 = {4c 75 6d 6d 61 43 32 } //1 LummaC2
		$a_01_2 = {6c 75 6d 6d 61 6e 6f 77 6f 72 6b } //1 lummanowork
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}