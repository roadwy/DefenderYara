
rule Trojan_Win32_Mokes_SPSB_MTB{
	meta:
		description = "Trojan:Win32/Mokes.SPSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d b5 f8 fb ff ff c7 85 f8 fb ff ff 00 00 00 00 e8 ?? ?? ?? ?? 8a 95 f8 fb ff ff 8b 85 f4 fb ff ff 30 14 38 83 fb 0f 75 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}