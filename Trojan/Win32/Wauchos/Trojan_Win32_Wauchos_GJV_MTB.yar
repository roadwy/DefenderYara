
rule Trojan_Win32_Wauchos_GJV_MTB{
	meta:
		description = "Trojan:Win32/Wauchos.GJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 55 ec a1 ?? ?? ?? ?? 89 82 ?? ?? ?? ?? 8b 4d f0 83 e9 39 0f b6 15 ?? ?? ?? ?? 2b ca 33 c0 89 0d 18 24 42 00 a3 } //10
		$a_01_1 = {73 61 62 66 72 61 20 74 6d 65 65 65 6d 68 63 43 6d 72 74 6a 65 68 } //1 sabfra tmeeemhcCmrtjeh
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}