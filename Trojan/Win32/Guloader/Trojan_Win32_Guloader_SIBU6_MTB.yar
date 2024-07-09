
rule Trojan_Win32_Guloader_SIBU6_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SIBU6!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f8 81 34 1a ?? ?? ?? ?? [0-40] 43 [0-30] 43 [0-2a] 43 [0-30] 43 [0-35] 81 fb b0 0d 01 00 [0-2a] 0f 85 a9 fe ff ff 90 08 b5 01 ff d2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}