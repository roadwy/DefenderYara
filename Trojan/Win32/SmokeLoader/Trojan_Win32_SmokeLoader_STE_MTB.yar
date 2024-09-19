
rule Trojan_Win32_SmokeLoader_STE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.STE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 33 f6 85 db 7e ?? 83 a5 f8 fb ff ff 00 8d 8d f8 fb ff ff e8 ?? ?? ?? ?? 8a 85 f8 fb ff ff 30 04 37 83 fb 0f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}