
rule Trojan_Win32_Vidar_SV_MTB{
	meta:
		description = "Trojan:Win32/Vidar.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 64 89 85 90 01 02 ff ff 83 ad 90 01 02 ff ff 64 8a 95 90 01 02 ff ff 8b 85 90 01 02 ff ff 30 14 30 83 ff 0f 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}