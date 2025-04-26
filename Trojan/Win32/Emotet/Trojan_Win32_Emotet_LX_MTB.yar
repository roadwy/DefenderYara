
rule Trojan_Win32_Emotet_LX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.LX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 4d 17 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 45 e8 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d e4 89 45 e8 0f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}