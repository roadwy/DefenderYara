
rule Trojan_Win32_Guloader_SIBU9_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU9!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 81 34 07 b8 d6 f9 ac [0-aa] 83 c0 04 [0-a0] 3d 0c 15 01 00 [0-35] 0f 85 d0 fd ff ff [0-9a] ff d7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}