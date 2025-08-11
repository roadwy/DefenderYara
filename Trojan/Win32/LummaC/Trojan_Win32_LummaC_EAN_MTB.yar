
rule Trojan_Win32_LummaC_EAN_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {29 d0 8b 55 f0 04 e6 8b 75 e8 88 84 0e 1c 8a ef d9 41 4a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}