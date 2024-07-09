
rule Trojan_Win32_Dridex_DEK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 ce 03 d1 89 15 ?? ?? ?? ?? 8b 74 24 0c 8b 4c 24 10 81 c1 ?? ?? ?? ?? 89 4c 24 10 89 0e be ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 4c 24 14 2b f1 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}