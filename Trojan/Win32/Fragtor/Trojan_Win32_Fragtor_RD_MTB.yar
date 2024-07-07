
rule Trojan_Win32_Fragtor_RD_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 95 20 4f 09 8b ce f7 ee d1 fa 8b c2 c1 e8 1f 03 c2 6b c0 37 2b c8 83 c1 35 66 31 8c 75 10 c2 ff ff 46 81 fe b6 1e 00 00 7c d5 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}