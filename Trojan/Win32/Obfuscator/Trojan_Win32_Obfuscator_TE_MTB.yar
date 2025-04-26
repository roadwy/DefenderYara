
rule Trojan_Win32_Obfuscator_TE_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.TE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 18 40 89 44 24 18 8a 54 14 20 30 50 ff 39 ac 24 ?? ?? ?? ?? 0f ?? ?? ?? ?? ?? 8b 44 24 1c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}