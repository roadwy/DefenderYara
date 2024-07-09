
rule Trojan_Win32_Stealc_RTF_MTB{
	meta:
		description = "Trojan:Win32/Stealc.RTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d0 88 45 ?? 0f b6 45 bb 0f b6 84 05 ?? ?? ?? ?? 88 45 ba 8b 55 bc 8b 45 e4 01 d0 0f b6 00 32 45 ba 88 45 ?? 8b 55 bc 8b 45 e0 01 c2 0f b6 45 ?? 88 02 83 45 ?? ?? 8b 45 dc 3b 45 ?? 0f 8f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}