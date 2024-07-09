
rule Trojan_Win32_Emotetcrypt_VG_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff d6 53 53 ff d6 8b 45 [0-02] 8a 0c [0-02] 02 4d [0-02] 8b 45 [0-02] 8b 55 [0-02] 32 0c [0-02] 88 08 40 ff 4d [0-02] 89 45 [0-02] 0f 85 [0-04] 5f 5e 5b c9 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotetcrypt_VG_MTB_2{
	meta:
		description = "Trojan:Win32/Emotetcrypt.VG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b6 4c 24 ?? 8b d5 2b 15 ?? ?? ?? ?? 45 03 c2 8b 15 ?? ?? ?? ?? 8a 0c ?? 30 ?? 3b 6c ?? ?? 0f 8c } //1
		$a_02_1 = {0f b6 c2 8a ?? ?? 30 ?? ?? b9 ?? ?? ?? ?? 8b 7d ?? 47 89 7d ?? 3b 7d ?? 7c 90 0a 32 00 03 [0-0f] f7 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}