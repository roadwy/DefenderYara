
rule Trojan_Win32_Obfuscator_PJ_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.PJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d 74 30 04 31 b8 ?? ?? ?? ?? 83 f0 ?? 83 6d 74 ?? 83 7d 74 ?? ?? ?? ?? ?? ?? ?? 5e 83 c5 ?? c9 c3 55 8b ec 83 ec ?? 68 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}