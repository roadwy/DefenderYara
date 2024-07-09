
rule Trojan_Win32_PlugxCrypt_BA_MTB{
	meta:
		description = "Trojan:Win32/PlugxCrypt.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {99 f7 7c 24 90 0a 09 00 8b c1 [0-08] 99 [0-05] f7 7c 24 ?? 8a 04 2a 8a 14 31 32 d0 [0-08] 88 14 31 [0-14] 41 3b cf [0-04] 7c } //10
		$a_03_1 = {99 f7 7c 24 ?? 90 0a 0a 00 8b c1 [0-0a] 99 f7 7c 24 ?? 8a 04 2a 8a 14 31 32 d0 88 14 31 41 3b cf 7c e6 } //10
		$a_03_2 = {85 c0 c6 44 24 [0-02] c6 44 24 [0-02] c6 44 24 [0-02] c6 44 24 [0-02] c6 44 24 [0-02] c6 44 24 [0-02] c6 44 24 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*1) >=10
 
}