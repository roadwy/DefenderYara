
rule Trojan_Win32_CryptInject_LP_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.LP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 c7 45 fc 00 00 00 00 64 a1 30 00 00 00 8b 40 0c 8b 40 14 8b 00 8b 40 10 89 45 fc 8b 45 fc 8b e5 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}