
rule Trojan_Win32_Dridex_ZZ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {3d 12 35 09 00 77 07 cc cc 40 cc cc eb f2 } //1
		$a_03_1 = {77 07 cc cc 40 cc cc eb f2 90 09 05 00 3d ?? ?? 09 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}