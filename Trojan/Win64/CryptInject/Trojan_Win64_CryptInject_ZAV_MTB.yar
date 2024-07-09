
rule Trojan_Win64_CryptInject_ZAV_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.ZAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 c0 45 8d 48 01 8b 05 b0 3c 0b 00 8b 4f 28 33 0d bf 3c 0b 00 81 e9 58 26 1b 00 0f af c1 89 05 98 3c 0b 00 48 8b 87 a8 00 00 00 41 8b 14 00 49 83 c0 04 0f af 57 6c 8b 87 ?? ?? ?? ?? 83 e8 0d 09 47 50 8b 47 08 01 05 4c 3b 0b 00 48 8b 05 ed 3b 0b 00 48 63 8f ?? ?? ?? ?? 88 14 01 b9 94 0a 16 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}