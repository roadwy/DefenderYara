
rule Trojan_Win32_Emotet_RDS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.RDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d ?? 89 45 ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}