
rule Trojan_Win32_Adload_D_MTB{
	meta:
		description = "Trojan:Win32/Adload.D!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 00 00 00 00 ff 34 24 59 52 89 0c 24 89 3c 24 89 e7 81 c7 04 00 00 00 81 c7 04 00 00 00 87 3c 24 5c 68 ae af fa 27 89 14 24 ba 39 73 eb 5c 81 ca ce ae f3 6f 81 c2 04 20 d7 6d f7 d2 c1 e2 05 c1 e2 02 81 f2 b6 fe 6f 16 29 d1 ff 34 24 5a 51 89 e1 81 c1 04 00 00 00 83 c1 04 87 0c 24 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}