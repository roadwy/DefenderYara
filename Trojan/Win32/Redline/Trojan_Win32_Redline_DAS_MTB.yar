
rule Trojan_Win32_Redline_DAS_MTB{
	meta:
		description = "Trojan:Win32/Redline.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 08 f6 17 80 37 43 47 e2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}