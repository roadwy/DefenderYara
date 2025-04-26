
rule Trojan_Win32_SmkLdr_B_MTB{
	meta:
		description = "Trojan:Win32/SmkLdr.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 00 98 40 38 18 75 f8 } //1
		$a_03_1 = {66 01 08 8d 40 02 66 39 18 75 f0 90 09 05 00 b9 ?? ?? 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}