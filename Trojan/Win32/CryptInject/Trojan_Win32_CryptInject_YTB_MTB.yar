
rule Trojan_Win32_CryptInject_YTB_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.YTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 10 8b c8 e8 ?? ?? ff ff 6a 1e ff d7 83 ee 01 75 ea } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}