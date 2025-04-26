
rule Trojan_Win32_Madokwa_MKV_MTB{
	meta:
		description = "Trojan:Win32/Madokwa.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 c1 2d 73 18 00 00 89 d0 03 85 a2 fe ff ff 89 8d ?? ?? ?? ?? 89 45 ab 8b 8d a3 fe ff ff 31 4d ee 0f b7 c0 8d 55 e6 2b 8d 2e ff ff ff } //1
		$a_03_1 = {ba db 77 00 00 03 8d f0 fe ff ff 89 8d a7 fe ff ff 33 55 d6 89 8d 71 ff ff ff 8b 45 b4 b9 7d 08 00 00 3b 05 ?? ?? ?? ?? 78 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}