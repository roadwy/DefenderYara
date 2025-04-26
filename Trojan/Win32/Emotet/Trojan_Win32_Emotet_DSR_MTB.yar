
rule Trojan_Win32_Emotet_DSR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8b 44 24 ?? 83 c4 10 8a 54 14 ?? 32 da 88 5d 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}