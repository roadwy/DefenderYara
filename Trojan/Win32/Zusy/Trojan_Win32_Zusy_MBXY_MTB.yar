
rule Trojan_Win32_Zusy_MBXY_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MBXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 6e 69 00 72 69 6f 74 63 6c 69 65 6e 74 3a 2f 2f 52 69 6f 74 43 6c 69 65 6e 74 53 65 72 76 69 63 65 73 2e 65 78 65 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}