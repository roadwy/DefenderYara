
rule Trojan_Win32_LaplasClipper_D_MTB{
	meta:
		description = "Trojan:Win32/LaplasClipper.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {f6 17 80 07 ?? fe 07 47 e2 f6 } //2
		$a_03_1 = {33 c2 83 c1 ?? a9 ?? ?? ?? ?? 74 90 09 0c 00 8b 01 ba ?? ?? ?? ?? 03 d0 83 f0 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}