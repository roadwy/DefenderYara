
rule Trojan_Win32_Azorult_SF_MTB{
	meta:
		description = "Trojan:Win32/Azorult.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 40 6b c0 00 c6 80 90 01 04 6b 33 c0 40 6b c0 0a c6 80 90 01 04 6c 33 c0 40 6b c0 06 c6 80 90 01 04 33 33 c0 40 6b c0 03 c6 80 90 01 04 6e 33 c0 40 c1 e0 02 c6 80 90 01 04 65 90 00 } //1
		$a_02_1 = {6a 04 58 6b c0 00 8b 4d 90 01 01 8b 04 01 89 45 90 01 01 6a 04 58 c1 e0 00 8b 4d 90 01 01 8b 04 01 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}