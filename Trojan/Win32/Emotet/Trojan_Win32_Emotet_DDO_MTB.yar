
rule Trojan_Win32_Emotet_DDO_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a cb 8a c2 f6 d1 f6 d0 0a da 0a c8 be ?? ?? ?? ?? 8b 45 ?? 22 cb 8b 5d ?? 88 0b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}