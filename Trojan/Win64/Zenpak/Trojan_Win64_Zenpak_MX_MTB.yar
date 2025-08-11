
rule Trojan_Win64_Zenpak_MX_MTB{
	meta:
		description = "Trojan:Win64/Zenpak.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 00 41 03 49 8d 0c 31 49 8b c0 48 f7 e1 48 c1 ea 02 48 8d 04 92 48 2b c8 0f b6 44 0d 20 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}