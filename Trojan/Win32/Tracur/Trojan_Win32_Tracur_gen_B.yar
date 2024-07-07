
rule Trojan_Win32_Tracur_gen_B{
	meta:
		description = "Trojan:Win32/Tracur.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 18 8b f0 5f 5b 85 f6 74 21 8b 06 8b 48 28 85 c9 74 18 8b 46 04 03 c1 74 11 6a ff 6a 01 6a 00 ff d0 85 c0 75 05 e8 90 01 04 5e 33 c0 40 c9 c2 08 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}