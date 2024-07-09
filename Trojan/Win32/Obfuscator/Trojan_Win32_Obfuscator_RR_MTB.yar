
rule Trojan_Win32_Obfuscator_RR_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 44 34 20 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c4 ?? 45 0f b6 54 14 14 30 55 ff 83 bc 24 ?? ?? ?? ?? ?? ?? ?? 8b 44 24 10 5e 5d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}