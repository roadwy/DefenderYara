
rule Trojan_Win32_Zenpak_BX_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c2 48 48 01 1d ?? ?? ?? ?? 42 8d 05 ?? ?? ?? ?? 01 38 8d 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}