
rule Trojan_Win32_Vidar_KLS_MTB{
	meta:
		description = "Trojan:Win32/Vidar.KLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 8b 85 f4 f7 ff ff 83 c0 ?? 89 85 f8 f7 ff ff 83 ad f8 f7 ff ff 64 8a 8d f8 f7 ff ff 30 0c 33 83 ff 0f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}