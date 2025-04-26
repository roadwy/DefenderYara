
rule Trojan_Win32_Farfli_BAU_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 65 c4 00 6a 6b 53 c7 45 b4 30 00 00 00 c7 45 b8 03 00 00 00 c7 45 bc [0-04] 89 5d c8 ff d6 68 00 7f 00 00 6a 00 89 45 cc ff 15 [0-04] 6a 6c ff 75 c8 89 45 d0 c7 45 d4 06 00 00 00 c7 45 d8 6d 00 00 00 89 7d dc ff d6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}