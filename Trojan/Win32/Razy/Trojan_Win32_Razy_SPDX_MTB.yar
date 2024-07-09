
rule Trojan_Win32_Razy_SPDX_MTB{
	meta:
		description = "Trojan:Win32/Razy.SPDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 e0 ea 40 00 bf d2 d5 63 a9 e8 ?? ?? ?? ?? 29 fb 31 0a 01 df 47 81 c2 01 00 00 00 47 89 fb 39 c2 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}