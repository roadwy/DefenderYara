
rule Trojan_Win32_Emotet_DEO_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 81 e2 ff 00 00 00 8a 84 0c ?? ?? ?? ?? b9 3d 23 00 00 03 c2 99 f7 f9 8b 84 24 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 8a 94 14 90 1b 00 30 14 08 } //1
		$a_81_1 = {67 37 68 76 33 4d 67 39 70 33 62 4c 57 44 61 68 76 4a 50 57 74 61 42 49 77 77 57 79 51 6a 52 32 79 6c 4a 79 6d 4c 57 } //1 g7hv3Mg9p3bLWDahvJPWtaBIwwWyQjR2ylJymLW
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}