
rule Trojan_Win32_Zenpak_RO_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 56 8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8a 24 0a 28 c4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 24 0e 5e 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}