
rule Trojan_Win32_CryptBot_BM_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 51 08 32 51 19 88 50 08 c6 05 } //2
		$a_03_1 = {8b 4c 24 08 8b 44 24 04 0f b6 11 32 51 ?? 88 10 0f b6 51 01 32 51 } //2
		$a_01_2 = {74 2e 6d 65 2f 6d 30 38 6d 62 6b } //1 t.me/m08mbk
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}