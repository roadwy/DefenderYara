
rule Trojan_Win32_StealC_SPCO_MTB{
	meta:
		description = "Trojan:Win32/StealC.SPCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ff 2d 75 0a 8d 4d dc 51 ff 15 90 01 04 e8 90 01 04 30 04 33 46 3b f7 7c e4 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}