
rule Trojan_Win32_DCRat_RE_MTB{
	meta:
		description = "Trojan:Win32/DCRat.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 0f b6 c1 8a 84 05 ?? fe ff ff 32 86 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? c7 45 fc ff ff ff ff 8b 85 ?? fe ff ff 8b 8d ?? fe ff ff 46 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}