
rule Trojan_Win32_Vidar_AMK_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 44 3c ?? 03 c6 59 8b 4c 24 ?? 0f b6 c0 8a 44 04 ?? 30 04 29 45 3b 2b 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}