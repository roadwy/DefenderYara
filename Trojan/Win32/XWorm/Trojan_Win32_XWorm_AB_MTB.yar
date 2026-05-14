
rule Trojan_Win32_XWorm_AB_MTB{
	meta:
		description = "Trojan:Win32/XWorm.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {85 c9 74 09 33 d2 48 ff 25 83 56 05 00 [0-04] 48 83 ec 28 8b 15 5e 7e 12 00 33 c9 41 b9 04 00 00 00 41 b8 00 20 20 00 ff 15 32 55 05 00 48 85 c0 74 18 33 d2 41 b8 00 80 00 00 48 8b c8 ff 15 24 55 05 00 b0 01 48 83 c4 28 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}