
rule Trojan_Win32_Zenpak_AB_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 4d dc 8b 4d dc 33 4d e0 89 4d e0 8b 4d e0 03 4d e8 89 4d e8 8b 45 e4 05 ?? ?? ?? ?? 89 45 e4 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}