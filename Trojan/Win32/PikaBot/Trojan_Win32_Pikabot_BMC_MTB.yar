
rule Trojan_Win32_Pikabot_BMC_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.BMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 ca 8b 85 fc fe ff ff 03 85 44 ff ff ff 2b 85 14 ff ff ff 03 45 fc 03 45 bc 03 85 44 ff ff ff 2b 85 14 ff ff ff 03 45 fc 03 45 bc 03 85 44 ff ff ff 2b 85 14 ff ff ff 03 45 fc 03 45 bc 8b 95 0c ff ff ff 88 0c 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}