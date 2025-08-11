
rule Trojan_Win32_Zenpak_GTY_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GTY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 d0 31 d2 89 15 ?? ?? ?? ?? 01 35 ?? ?? ?? ?? 42 29 c2 01 c2 8d 05 ?? ?? ?? ?? 31 d2 89 10 31 18 e8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}