
rule Trojan_Win32_Hancitor_PH_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b 45 d8 8b 00 03 45 e8 03 d8 e8 ?? ?? ?? ?? 2b d8 8b 45 d8 89 18 8b 45 c8 03 45 a8 03 45 e8 8b 55 d8 31 02 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}