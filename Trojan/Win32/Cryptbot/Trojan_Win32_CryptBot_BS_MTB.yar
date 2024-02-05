
rule Trojan_Win32_CryptBot_BS_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {47 23 fe 8d 44 3d 88 0f b6 08 03 4d 84 23 ce 89 4d 84 8d 4c 0d 88 8a 11 30 10 8a 10 30 11 8a 11 30 10 0f b6 00 0f b6 09 8b 55 80 03 c1 23 c6 8a 44 05 88 03 d3 30 02 43 3b 9d 98 00 00 00 72 } //00 00 
	condition:
		any of ($a_*)
 
}