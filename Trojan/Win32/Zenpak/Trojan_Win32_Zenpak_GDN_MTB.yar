
rule Trojan_Win32_Zenpak_GDN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 d0 8d 05 ?? ?? ?? ?? 89 20 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? c3 48 31 d0 48 31 1d ?? ?? ?? ?? 01 35 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}