
rule Trojan_Win32_CryptBot_MA_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 0c 8d 4e 01 8a 04 06 88 04 1a 8b c2 33 d2 8b 75 18 f7 75 14 ff 45 fc 03 f1 85 d2 8b 55 fc 0f 45 f1 3b 55 10 72 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}