
rule Trojan_Win32_Vidar_CCGR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.CCGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c7 f7 f1 8b 45 ?? 8b 4d ?? 03 c7 47 8a 92 ?? ?? ?? ?? 32 14 08 88 10 83 ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}