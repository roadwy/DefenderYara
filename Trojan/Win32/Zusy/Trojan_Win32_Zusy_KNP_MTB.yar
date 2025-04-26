
rule Trojan_Win32_Zusy_KNP_MTB{
	meta:
		description = "Trojan:Win32/Zusy.KNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ce b8 b5 d9 dd 0d 83 e1 07 ba 71 ff 4b a1 c1 e1 03 e8 e4 48 00 00 30 04 3e 83 c6 01 83 d3 00 75 05 83 fe 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}