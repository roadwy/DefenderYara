
rule Trojan_Win32_Emotet_DDI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8b 4d ?? 0f b6 04 32 8b 55 ?? 8a d8 f6 d3 0f be 14 0a 89 55 ?? 0a 45 ?? f6 d2 0a da 22 d8 88 19 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}