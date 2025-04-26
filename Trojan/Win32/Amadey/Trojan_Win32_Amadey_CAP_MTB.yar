
rule Trojan_Win32_Amadey_CAP_MTB{
	meta:
		description = "Trojan:Win32/Amadey.CAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 28 01 44 24 0c 8b c6 c1 e8 05 c7 05 [0-04] 19 36 6b ff c7 05 [0-04] ff ff ff ff 89 44 24 10 8b 44 24 20 01 44 24 10 8d 0c 33 31 4c 24 0c 8b 44 24 10 31 44 24 0c 8b 44 24 0c 29 44 24 14 81 3d [0-04] 93 00 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}