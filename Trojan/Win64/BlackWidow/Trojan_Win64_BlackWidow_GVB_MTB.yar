
rule Trojan_Win64_BlackWidow_GVB_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 2b c8 0f b6 44 0c 20 43 32 44 0c fb 41 88 41 fb } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}