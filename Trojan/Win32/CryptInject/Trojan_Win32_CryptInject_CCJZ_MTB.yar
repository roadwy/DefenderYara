
rule Trojan_Win32_CryptInject_CCJZ_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CCJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {99 83 e2 1f 01 d0 c1 f8 05 83 e8 01 0f b6 44 05 ?? 31 c8 88 45 ?? c7 45 } //6
		$a_03_1 = {01 ca 0f b6 1a 8d 4d ?? 8b 55 ?? 01 ca 0f b6 12 31 da 88 10 83 45 ?? 01 83 7d ?? 03 7e } //4
		$a_01_2 = {50 41 59 4c 4f 41 44 5f } //1 PAYLOAD_
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4+(#a_01_2  & 1)*1) >=11
 
}