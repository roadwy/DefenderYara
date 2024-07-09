
rule Trojan_Win32_Dridex_DEU_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d8 2b da 8b 15 ?? ?? ?? ?? 8d 54 13 02 8b 6c 24 10 8b d8 2b d9 03 fb 8b 1d ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 89 1d 90 1b 01 89 5d 00 8b 1d 90 1b 00 2b 1d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}