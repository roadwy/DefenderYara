
rule Trojan_Win32_TrickBotCrypt_MY_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {f6 d0 8b ce 3b 90 01 01 73 90 01 01 eb 90 01 01 8d 90 01 02 8a 90 01 01 2a 90 01 01 32 90 01 01 32 90 01 01 88 90 01 01 03 90 01 02 3b 90 01 01 72 90 01 01 8b 90 01 02 46 ff 90 01 02 90 18 8a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}