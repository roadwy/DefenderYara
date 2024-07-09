
rule Trojan_Win32_Cridex_CY_MTB{
	meta:
		description = "Trojan:Win32/Cridex.CY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {30 0c 1e 56 e8 ?? ?? ?? ?? 8b f0 83 c4 04 85 ?? ?? ?? ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 5f 5e 5b 33 cc [0-10] c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}