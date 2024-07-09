
rule Trojan_Win32_Emotet_DBN_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 bd ?? ?? ?? ?? 0f b6 84 15 ?? ?? ?? ?? 8b 4d ?? 03 8d ?? ?? ?? ?? 0f b6 11 33 d0 8b 45 90 1b 02 03 85 90 1b 03 88 10 8b 8d 90 1b 03 83 c1 01 89 8d 90 1b 03 e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}