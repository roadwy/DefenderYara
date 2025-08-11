
rule Trojan_Win32_LummaC_EHI_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 95 64 ed ff ff 01 c2 83 c0 01 89 95 64 ed ff ff 3d 10 27 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}