
rule Trojan_Win32_Fareit_FTR_MTB{
	meta:
		description = "Trojan:Win32/Fareit.FTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 45 08 18 4e 50 54 81 6d 88 89 d4 9f 03 81 45 f0 27 b5 37 58 b8 8d bf d9 75 f7 65 8c 8b 45 8c 81 ad cc fe ff ff 68 6c 98 55 89 75 74 b8 3b 2d 0b 00 01 45 74 8b 45 74 8a 04 08 88 04 39 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}