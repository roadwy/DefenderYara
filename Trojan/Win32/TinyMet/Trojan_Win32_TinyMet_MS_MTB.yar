
rule Trojan_Win32_TinyMet_MS_MTB{
	meta:
		description = "Trojan:Win32/TinyMet.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 08 56 8b 45 90 01 01 89 45 90 01 01 c7 45 90 01 05 8b 4d 90 01 01 69 c9 90 01 04 89 4d 90 01 01 8b 55 90 01 01 81 ea 90 01 04 89 55 90 01 01 a1 90 01 04 89 45 90 00 } //1
		$a_02_1 = {89 02 5f 5d c3 90 0a 2d 00 31 0d 90 01 04 c7 05 90 02 08 a1 90 01 04 01 05 90 02 06 8b 15 90 01 04 a1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}