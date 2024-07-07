
rule Trojan_Win32_Obfuscator_TB_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.TB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8b 85 90 01 04 40 83 c4 90 01 01 89 85 90 01 04 0f b6 94 15 90 01 04 30 50 ff 83 7d 14 90 01 01 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}