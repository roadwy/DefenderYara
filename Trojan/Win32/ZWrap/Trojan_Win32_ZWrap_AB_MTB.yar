
rule Trojan_Win32_ZWrap_AB_MTB{
	meta:
		description = "Trojan:Win32/ZWrap.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 8a 0c 02 8b 44 ?? ?? 8b 7c ?? ?? 30 0c 38 40 3b 44 ?? ?? 89 44 ?? ?? 0f [0-06] 8b 44 ?? ?? 8a 54 ?? ?? 8a 4c ?? ?? 5f 5e 5d [0-10] c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}