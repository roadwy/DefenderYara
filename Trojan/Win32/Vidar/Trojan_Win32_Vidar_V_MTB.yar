
rule Trojan_Win32_Vidar_V_MTB{
	meta:
		description = "Trojan:Win32/Vidar.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 85 74 fb ff ff 8b 8d 60 fb ff ff 03 8d 80 fb ff ff 8d 58 04 0f af d8 8b 85 68 fb ff ff 0f af de 8b 15 4c 3f 42 00 0f af de 89 8d 50 fb ff ff 8b 8d 88 fb ff ff 8a 04 01 83 c3 90 01 01 32 c3 88 85 78 fb ff ff 89 95 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}