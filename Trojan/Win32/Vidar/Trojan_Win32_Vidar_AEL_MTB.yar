
rule Trojan_Win32_Vidar_AEL_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 cb 0f b6 c1 88 8d ?? ?? ff ff 8d 8d cc fe ff ff 03 c8 0f b6 01 88 02 88 19 0f b6 02 8b 8d bc fe ff ff 02 c3 0f b6 c0 0f b6 84 05 cc fe ff ff 30 04 0e 46 8a 8d cb fe ff ff 3b f7 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}