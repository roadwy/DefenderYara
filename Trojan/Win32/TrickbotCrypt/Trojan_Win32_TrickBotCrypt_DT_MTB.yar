
rule Trojan_Win32_TrickBotCrypt_DT_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.DT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 08 8b 55 ?? 8b 02 8b 55 ?? 8b 75 ?? 8a 0c 0a 32 0c 06 8b 55 ?? 8b 02 8b 55 ?? 88 0c 02 e9 90 09 03 00 8b 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}