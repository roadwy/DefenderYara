
rule Trojan_Win32_Slepak_MX_MTB{
	meta:
		description = "Trojan:Win32/Slepak.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 c0 ef 0d 00 00 8b 37 66 2b d0 a1 ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? 81 c6 70 3b 07 01 33 d2 89 35 ?? ?? ?? ?? 3b 15 ?? ?? ?? ?? 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}