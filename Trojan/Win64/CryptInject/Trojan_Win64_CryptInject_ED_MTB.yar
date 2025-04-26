
rule Trojan_Win64_CryptInject_ED_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {4d 8b f7 33 03 25 ?? ?? ?? ?? 41 31 45 ?? 0f b6 43 ?? 41 08 45 ?? eb } //1
		$a_03_1 = {41 8d 80 20 ?? ?? ?? 48 83 c1 ?? 33 41 ?? 41 89 44 09 ?? 44 8b 87 ?? ?? ?? ?? 41 8d 80 ?? ?? ?? ?? 31 41 ?? 48 ff ca 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}