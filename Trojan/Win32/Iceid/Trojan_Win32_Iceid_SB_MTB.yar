
rule Trojan_Win32_Iceid_SB_MTB{
	meta:
		description = "Trojan:Win32/Iceid.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 8d 05 ?? ?? ?? ?? ff d0 59 83 f8 00 0f 90 0a 50 00 8d 0d ?? ?? ?? ?? 51 6a ?? 83 04 24 ?? 68 ?? ?? 00 00 83 04 24 ?? 68 ?? ?? 00 00 83 04 24 ?? 6a 00 8d 05 ?? ?? ?? ?? ff d0 59 83 f8 00 0f 90 0a 50 00 } //1
		$a_03_1 = {89 ec 5d f1 ff 35 ?? ?? ?? ?? c3 ff 35 ?? ?? ?? ?? c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}