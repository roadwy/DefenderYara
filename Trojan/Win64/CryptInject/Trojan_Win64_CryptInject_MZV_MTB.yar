
rule Trojan_Win64_CryptInject_MZV_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.MZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ea 08 ff 40 50 48 8b 05 42 99 01 00 8b 88 ?? ?? ?? ?? 33 4b 0c ff c9 09 8b 98 00 00 00 48 8b 05 2a 99 01 00 8b 88 ?? ?? ?? ?? 8b 40 48 05 b7 0b f0 ff 03 c8 48 8b 83 ?? ?? ?? ?? 31 4b 40 48 63 0d 69 99 01 00 88 14 01 ff 05 60 99 01 00 48 8b 15 f9 98 01 00 8b 82 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}