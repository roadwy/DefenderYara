
rule Trojan_Win32_SolarMark_JLA_MTB{
	meta:
		description = "Trojan:Win32/SolarMark.JLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b1 10 8b 1d 90 01 02 44 00 8b c3 bf 0a 00 00 00 99 f7 ff 80 c2 30 33 c0 8a c1 88 14 06 8b c3 bb 0a 00 00 00 99 f7 fb 8b d8 49 85 db 75 db b1 1c a1 90 01 02 44 00 8b d0 83 e2 0f 8a 92 90 01 02 44 00 33 db 8a d9 88 14 1e c1 e8 04 49 85 c0 75 e6 90 00 } //1
		$a_03_1 = {00 bb 58 dd 44 00 8a 86 90 01 03 00 32 03 a2 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}