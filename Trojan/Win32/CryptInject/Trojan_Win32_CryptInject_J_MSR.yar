
rule Trojan_Win32_CryptInject_J_MSR{
	meta:
		description = "Trojan:Win32/CryptInject.J!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 89 45 f4 90 90 90 8b 45 c0 89 45 e4 90 90 90 90 90 8b 45 f4 01 45 e4 90 90 90 90 8b 45 e8 89 45 d8 90 90 90 90 8b 45 e4 89 45 dc 8b 45 d8 8a 80 5c ad 45 00 88 45 bf 90 c6 45 d3 71 90 90 90 8a 45 bf 32 45 d3 8b 55 dc 88 02 90 90 90 90 ff 45 e8 81 7d e8 ab 5d 00 00 75 95 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}