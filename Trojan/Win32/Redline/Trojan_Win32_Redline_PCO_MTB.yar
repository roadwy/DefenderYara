
rule Trojan_Win32_Redline_PCO_MTB{
	meta:
		description = "Trojan:Win32/Redline.PCO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 e2 89 74 24 28 03 54 24 48 8b 44 24 14 01 44 24 28 8b 44 24 18 01 44 24 28 8b 44 24 28 89 44 24 1c 8b 44 24 18 8b 4c 24 20 d3 e8 89 44 24 10 8b 44 24 3c 01 44 24 10 33 54 24 1c 8d 4c 24 30 89 54 24 30 52 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}