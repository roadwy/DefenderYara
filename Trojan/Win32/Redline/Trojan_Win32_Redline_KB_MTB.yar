
rule Trojan_Win32_Redline_KB_MTB{
	meta:
		description = "Trojan:Win32/Redline.KB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 e2 89 7c 24 20 03 54 24 3c 89 54 24 10 8b 44 24 2c 01 44 24 20 8b 44 24 18 90 01 44 24 20 8b 44 24 20 89 44 24 28 8b 44 24 18 8b 4c 24 1c d3 e8 89 44 24 14 8b 44 24 40 01 44 24 14 8b 4c 24 14 33 4c 24 28 8b 54 24 10 33 d1 8d 4c 24 30 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}