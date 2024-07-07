
rule Trojan_Win32_Redline_CCHF_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 30 00 00 8b 85 90 01 01 ff ff ff 8b 48 90 01 01 51 8b 95 90 01 01 fe ff ff 52 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}