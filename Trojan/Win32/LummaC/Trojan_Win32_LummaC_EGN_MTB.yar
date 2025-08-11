
rule Trojan_Win32_LummaC_EGN_MTB{
	meta:
		description = "Trojan:Win32/LummaC.EGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 0f b6 c0 8a 84 05 f8 fe ff ff 30 83 ?? ?? ?? ?? 43 81 fb } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}