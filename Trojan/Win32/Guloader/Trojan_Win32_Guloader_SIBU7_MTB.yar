
rule Trojan_Win32_Guloader_SIBU7_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU7!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 81 34 07 ?? ?? ?? ?? [0-aa] 83 c0 04 [0-b0] 3d 74 1a 01 00 [0-30] 0f 85 ca fd ff ff [0-aa] ff d7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}