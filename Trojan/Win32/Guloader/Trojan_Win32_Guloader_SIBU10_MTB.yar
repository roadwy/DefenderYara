
rule Trojan_Win32_Guloader_SIBU10_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU10!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {71 81 34 07 ?? ?? ?? ?? [0-ac] 83 c0 04 [0-a0] 3d 74 18 01 00 [0-2a] 0f 85 e8 fd ff ff [0-95] ff d7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}