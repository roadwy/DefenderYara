
rule Trojan_Win32_Redline_CCHF_MTB{
	meta:
		description = "Trojan:Win32/Redline.CCHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 30 00 00 8b 85 ?? ff ff ff 8b 48 ?? 51 8b 95 ?? fe ff ff 52 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}