
rule Trojan_Win32_AntiAV_MR_MTB{
	meta:
		description = "Trojan:Win32/AntiAV.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c3 c1 e8 ?? 03 44 24 ?? 8d 3c 1e 33 cf c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 ?? 81 fa ?? ?? ?? ?? 75 } //1
		$a_02_1 = {5f 5e 89 68 ?? 5d 89 18 5b 33 cc e8 ?? ?? ?? ?? 81 c4 ?? ?? ?? ?? c2 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}