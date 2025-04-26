
rule Trojan_Win64_CryptInject_NIG_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.NIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 98 48 8d 14 85 ?? ?? ?? ?? 48 8b 45 18 48 01 d0 8b 00 8b 55 f8 48 63 d2 48 8d 0c 95 ?? ?? ?? ?? 48 8b 55 18 48 01 ca 33 45 f4 89 02 83 45 f8 01 8b 45 ec 83 c0 01 c1 e0 02 39 45 f8 0f 8c } //1
		$a_03_1 = {48 63 d0 48 8b 85 ?? ?? ?? ?? 48 01 d0 0f b6 00 0f b6 c0 8b 95 ?? ?? ?? ?? 48 63 ca 48 8b 95 a0 00 00 00 48 01 ca 48 98 0f b6 44 05 80 88 02 83 85 ?? ?? ?? ?? 01 8b 85 8c 00 00 00 48 98 48 3b 85 a8 00 00 00 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}