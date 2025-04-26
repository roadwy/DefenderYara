
rule Trojan_Win32_Alureon_DD{
	meta:
		description = "Trojan:Win32/Alureon.DD,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f0 69 c6 45 f1 27 c6 45 f2 6c c6 45 f3 6c c6 45 f4 20 c6 45 f5 62 c6 45 f6 65 c6 45 f7 20 c6 45 f8 62 c6 45 f9 61 c6 45 fa 63 c6 45 fb 6b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}