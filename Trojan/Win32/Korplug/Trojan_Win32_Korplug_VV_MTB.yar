
rule Trojan_Win32_Korplug_VV_MTB{
	meta:
		description = "Trojan:Win32/Korplug.VV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8b 94 95 e8 fb ff ff 8d 8d e0 fb ff ff 32 14 30 46 0f b6 d2 e8 af c7 ff ff e9 4b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}