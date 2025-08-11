
rule Trojan_Win32_Zenpak_SEZC_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.SEZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {22 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? 00 0f b6 c4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}