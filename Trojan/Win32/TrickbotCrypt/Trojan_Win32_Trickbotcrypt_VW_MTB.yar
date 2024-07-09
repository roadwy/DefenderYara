
rule Trojan_Win32_Trickbotcrypt_VW_MTB{
	meta:
		description = "Trojan:Win32/Trickbotcrypt.VW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 4c 24 ?? 8b [0-05] 8a ?? ?? 8b [0-08] 30 14 [0-06] 3b [0-05] 0f 8c [0-04] 8a ?? ?? ?? 8b ?? ?? ?? 8a ?? ?? ?? ?? ?? ?? 88 [0-0a] c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}