
rule Trojan_Win32_Emotetcrypt_VP_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 ec ?? c7 45 ?? ?? ?? ?? ?? 8b 45 ?? 33 45 ?? 89 45 ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 8b 4d ?? 83 ?? ?? 0f af 4d ?? 8b 45 ?? 99 f7 f9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VP_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 [0-02] 8b 0d [0-04] 8b 44 [0-02] 8a 14 [0-02] 30 14 [0-02] 8b 44 [0-02] 43 3b d8 0f 8c [0-04] 8a [0-04] 8b [0-04] 8a [0-04] 5f [0-02] 88 [0-02] 88 [0-02] 5b 59 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}