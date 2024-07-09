
rule Trojan_Win32_Zenpak_CCHT_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c2 02 8d 05 ?? ?? ?? ?? 01 20 29 d0 83 e8 01 e8 ?? ?? ?? ?? 42 89 d0 8d 05 ?? ?? ?? ?? 01 38 8d 05 ?? ?? ?? ?? ff e0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}