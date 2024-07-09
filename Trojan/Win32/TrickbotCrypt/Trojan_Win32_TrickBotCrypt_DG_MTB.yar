
rule Trojan_Win32_TrickBotCrypt_DG_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 0e 0f b6 d2 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 45 0c 0f b6 14 0a 02 15 ?? ?? ?? ?? 30 54 03 ff 3b 5d 10 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}