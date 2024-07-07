
rule Trojan_Win32_Vidar_OMJ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.OMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b 55 08 03 95 f4 fb ff ff 0f b6 02 8b 8d e4 f7 ff ff 33 84 8d f8 fb ff ff 8b 95 f0 fb ff ff 03 95 f4 fb ff ff 88 02 } //1
		$a_81_1 = {48 41 4c 39 54 48 } //1 HAL9TH
		$a_81_2 = {4a 6f 68 6e 44 6f 65 } //1 JohnDoe
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}