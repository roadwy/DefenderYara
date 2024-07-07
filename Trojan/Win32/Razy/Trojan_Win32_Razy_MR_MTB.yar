
rule Trojan_Win32_Razy_MR_MTB{
	meta:
		description = "Trojan:Win32/Razy.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec 08 56 8b 45 90 01 01 89 45 90 01 01 c7 45 90 01 05 8b 4d 90 01 01 69 c9 90 01 04 89 4d 90 01 01 8b 55 90 01 01 81 ea 90 01 04 89 55 90 01 01 a1 90 01 04 89 45 90 00 } //1
		$a_02_1 = {8b 45 08 03 30 8b 4d 08 89 31 68 90 01 04 6a 00 ff 15 90 01 04 05 90 01 04 8b 55 08 8b 0a 2b c8 8b 55 08 89 0a 5e 8b e5 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}