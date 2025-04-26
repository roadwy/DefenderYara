
rule Trojan_Win32_Razy_GNP_MTB{
	meta:
		description = "Trojan:Win32/Razy.GNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 5b 81 c7 ?? ?? ?? ?? 31 16 89 f9 01 df 81 c6 04 00 00 00 39 c6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}