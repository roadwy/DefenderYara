
rule Trojan_Win32_Doina_NA_MTB{
	meta:
		description = "Trojan:Win32/Doina.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {e8 64 fe ff ff c7 45 14 ?? ?? ?? ?? e9 e8 02 00 00 8b 45 ?? 39 45 f8 75 ec 83 f9 ff 0f 84 d7 02 00 00 8b 45 10 } //5
		$a_01_1 = {57 65 62 4d 20 50 72 6f 6a 65 63 74 20 56 50 38 20 45 6e 63 6f 64 65 72 20 76 30 2e 39 2e 35 2d 32 2d 67 37 35 35 65 32 61 32 } //1 WebM Project VP8 Encoder v0.9.5-2-g755e2a2
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}