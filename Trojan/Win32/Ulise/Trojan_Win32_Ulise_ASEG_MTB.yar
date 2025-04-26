
rule Trojan_Win32_Ulise_ASEG_MTB{
	meta:
		description = "Trojan:Win32/Ulise.ASEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 6a 14 8b c1 5e f7 f6 8b 45 08 8a 04 02 30 04 19 41 3b cf 72 } //2
		$a_01_1 = {81 ec 74 01 00 00 53 56 57 6a ff ff 35 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}