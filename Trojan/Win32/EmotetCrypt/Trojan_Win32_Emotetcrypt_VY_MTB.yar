
rule Trojan_Win32_Emotetcrypt_VY_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {59 8b d8 8b 0d [0-04] 33 d2 8b c1 f7 f3 03 55 ?? 8a 04 32 8b 55 ?? 32 04 ?? 8b 55 ?? 88 04 ?? ff 05 [0-04] 39 3d [0-04] 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VY_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d2 8a ?? ?? 90 17 03 01 01 01 30 32 33 ?? ?? 83 ?? ?? ?? 01 75 ?? 8b ?? ?? ?? 8a ?? ?? ?? 8a ?? ?? ?? 5f ?? ?? 88 [0-02] 88 [0-02] 5b 83 ?? ?? c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}