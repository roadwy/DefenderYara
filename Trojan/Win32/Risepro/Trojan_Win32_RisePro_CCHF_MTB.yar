
rule Trojan_Win32_RisePro_CCHF_MTB{
	meta:
		description = "Trojan:Win32/RisePro.CCHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8b 15 ?? ?? ?? ?? 32 c8 8b 3d ?? ?? ?? ?? 88 4d e8 3b d7 73 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}