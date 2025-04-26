
rule Trojan_Win32_Emotet_CN_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 6a 00 6a 00 ff d6 02 5c 24 ?? 8b 84 24 ?? ?? ?? ?? 0f b6 cb 8a 1c 07 8a 54 0c ?? 32 da 88 1c 07 8b 84 24 ?? ?? ?? ?? 47 3b f8 0f 8c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}