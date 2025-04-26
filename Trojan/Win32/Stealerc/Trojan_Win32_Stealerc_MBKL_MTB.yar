
rule Trojan_Win32_Stealerc_MBKL_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.MBKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 00 65 00 78 00 65 00 00 00 41 38 37 39 31 68 62 78 37 38 69 55 41 } //1
		$a_01_1 = {47 59 41 55 73 38 37 61 74 65 64 79 75 77 33 } //1 GYAUs87atedyuw3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}