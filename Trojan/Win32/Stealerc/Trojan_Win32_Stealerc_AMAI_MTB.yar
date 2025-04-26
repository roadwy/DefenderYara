
rule Trojan_Win32_Stealerc_AMAI_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.AMAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {47 0f b6 44 3c ?? 88 44 34 ?? 88 4c 3c ?? 0f b6 44 34 ?? 03 c2 0f b6 c0 0f b6 44 04 ?? 30 83 ?? ?? ?? ?? 43 81 fb ?? ?? ?? ?? 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}