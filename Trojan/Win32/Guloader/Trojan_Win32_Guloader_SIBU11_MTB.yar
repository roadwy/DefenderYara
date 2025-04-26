
rule Trojan_Win32_Guloader_SIBU11_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU11!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 81 34 07 ?? ?? ?? ?? [0-90] 83 c0 04 [0-9a] 3d ?? ?? ?? ?? [0-2a] 0f 85 ?? ?? ?? ?? [0-8a] ff d7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}