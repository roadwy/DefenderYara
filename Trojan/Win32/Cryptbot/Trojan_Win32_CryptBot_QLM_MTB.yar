
rule Trojan_Win32_CryptBot_QLM_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.QLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4d 08 2b 0d 90 01 04 33 4d 0c 83 c1 64 2b c9 33 4d 0c 2b 0d 90 01 04 89 4d 08 be 10 00 00 00 33 75 08 81 c6 90 01 04 33 75 0c 89 75 ec 90 00 } //10
		$a_02_1 = {8b 45 08 33 05 90 01 04 81 e8 90 01 04 03 05 90 01 04 89 45 fc 8b 45 08 81 c0 90 01 04 83 f0 90 01 01 81 e8 90 01 04 33 45 08 90 00 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10) >=20
 
}