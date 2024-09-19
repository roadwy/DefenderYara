
rule Trojan_Win32_Zenpak_MBXK_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.MBXK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 e5 8a 45 ?? 8a 4d ?? 88 0d [0-15] 30 c8 a2 [0-35] 0f b6 c0 } //1
		$a_01_1 = {37 00 39 00 4f 00 54 00 4a 00 31 00 4d 00 30 00 57 00 2e 00 64 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}