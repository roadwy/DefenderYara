
rule Trojan_Win32_SmokeLoader_TZZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.TZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 a5 f8 f7 ff ff 00 8d 8d f8 f7 ff ff e8 ?? ?? ?? ?? 8a 85 f8 f7 ff ff 30 04 37 83 fb 0f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}