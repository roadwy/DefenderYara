
rule Trojan_Win32_LaplasClipper_C_MTB{
	meta:
		description = "Trojan:Win32/LaplasClipper.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 75 90 01 01 0f b6 92 90 01 04 33 ca 88 4d 90 01 01 8b 45 90 01 01 03 45 90 01 01 8a 08 88 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}