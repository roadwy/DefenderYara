
rule Trojan_Win32_Fragtor_BG_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 37 68 53 37 5a 31 0f b7 d2 59 81 c6 59 66 79 46 ba 54 68 c0 53 81 f6 1e e2 b5 40 80 cb f9 81 c6 ff 9a 8a 79 51 66 b9 31 28 } //3
		$a_01_1 = {75 45 7a 25 45 6d 6e 4b } //1 uEz%EmnK
		$a_01_2 = {41 59 5a 53 73 6e 40 59 5f 6d 4b } //1 AYZSsn@Y_mK
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}