
rule PWS_Win32_Ldpinch_AV{
	meta:
		description = "PWS:Win32/Ldpinch.AV,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c6 99 2b c2 d1 f8 50 ff d7 46 81 fe ff ff 00 00 7c ed } //1
		$a_03_1 = {8b 74 07 09 03 75 f4 33 c9 39 4c 07 51 76 24 8a 50 08 02 55 ff 8a 04 31 f6 d0 32 d0 8a c1 ?? ?? f6 eb f6 d2 32 d0 88 14 31 8b 45 f8 41 3b 4c 07 51 72 dc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}