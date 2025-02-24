
rule Trojan_Win32_LummaStealer_SKE_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.SKE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 89 b5 10 f9 ff ff ff 15 80 02 44 00 89 ?? ?? ?? ff ff 33 db 8d 85 f0 f5 ff ff 89 ?? ?? ?? ff ff 50 53 ff 15 28 02 44 00 8b 35 30 02 44 00 eb 1a } //1
		$a_00_1 = {53 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 65 00 72 00 3a 00 20 00 53 00 63 00 72 00 65 00 65 00 6e 00 20 00 55 00 70 00 6c 00 6f 00 61 00 64 00 65 00 72 00 } //1 Screenshoter: Screen Uploader
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}