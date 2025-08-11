
rule Trojan_Win32_LummaC_ALMZ_MTB{
	meta:
		description = "Trojan:Win32/LummaC.ALMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 48 f4 f7 d9 1b c9 23 c8 51 6a 00 33 c0 38 45 b3 6a 00 6a 00 ff 75 b8 0f 94 c0 6a 01 83 c0 02 50 a1 70 9d 46 00 6a 10 68 ff 01 0f 00 50 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}