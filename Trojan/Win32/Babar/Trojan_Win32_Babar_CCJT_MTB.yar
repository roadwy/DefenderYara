
rule Trojan_Win32_Babar_CCJT_MTB{
	meta:
		description = "Trojan:Win32/Babar.CCJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d0 0f b6 18 0f b6 85 ?? ?? ff ff 0f b6 8c 05 ?? ?? ff ff 8b 95 ?? ?? ff ff 8b 45 ?? 01 d0 31 cb 89 da 88 10 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}