
rule Trojan_Win32_Redline_MAC_MTB{
	meta:
		description = "Trojan:Win32/Redline.MAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 4d ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 0c 33 ?? fc 33 d2 33 45 ?? 89 15 } //1
		$a_03_1 = {8b c3 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}