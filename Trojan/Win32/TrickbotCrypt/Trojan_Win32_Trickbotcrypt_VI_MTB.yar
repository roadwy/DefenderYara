
rule Trojan_Win32_Trickbotcrypt_VI_MTB{
	meta:
		description = "Trojan:Win32/Trickbotcrypt.VI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 4c 24 [0-01] 8b d5 2b 15 [0-04] 45 03 c2 8b 15 [0-04] 8a 0c [0-01] 90 17 04 01 01 01 01 31 32 30 33 ?? 3b 6c [0-02] 0f 8c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}