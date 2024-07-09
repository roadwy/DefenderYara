
rule Trojan_Win32_Rhadamanthys_KMS_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.KMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 cb 0f b6 c1 88 8d ea fc ff ff 8d 8d ec fc ff ff 03 c8 0f b6 01 88 02 88 19 0f b6 0a 0f b6 c3 03 c8 0f b6 c1 8b 8d ?? ?? ?? ?? 0f b6 84 05 ec fc ff ff 30 04 0e 46 8a 8d ea fc ff ff 3b f7 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}