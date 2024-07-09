
rule Trojan_Win32_IcedId_DAJ_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 5c 24 14 b0 a9 2a 05 ?? ?? ?? ?? 8b 74 24 10 2a c4 02 c8 89 1d ?? ?? ?? ?? 8b 44 24 28 89 35 ?? ?? ?? ?? 8b 38 81 c7 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}