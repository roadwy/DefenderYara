
rule Trojan_Win32_StealC_CCFV_MTB{
	meta:
		description = "Trojan:Win32/StealC.CCFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ff 2d 75 90 01 01 6a 00 ff 15 90 01 04 e8 90 01 04 30 04 33 83 ff 0f 75 90 01 01 6a 00 90 02 06 6a 00 6a 00 6a 00 6a 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}