
rule Trojan_Win32_SmokeLoader_CRIZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CRIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 04 24 8b 04 24 31 01 } //1
		$a_03_1 = {33 c7 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}