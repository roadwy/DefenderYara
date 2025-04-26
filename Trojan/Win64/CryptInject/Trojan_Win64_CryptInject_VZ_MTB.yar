
rule Trojan_Win64_CryptInject_VZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.VZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 0f b6 10 8b 45 fc 48 63 c8 48 8b 45 10 48 01 c8 83 f2 ?? 88 10 83 45 fc 01 8b 45 fc 3b 45 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}