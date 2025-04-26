
rule Trojan_Win32_Guloader_SIBU12_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU12!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 81 34 07 ?? ?? ?? ?? [0-3a] 83 c0 00 [0-80] 83 c0 04 [0-9d] 3d ?? ?? ?? ?? [0-35] 0f 85 ?? ?? ?? ?? [0-95] ff d7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}