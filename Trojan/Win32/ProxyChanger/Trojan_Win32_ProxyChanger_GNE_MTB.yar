
rule Trojan_Win32_ProxyChanger_GNE_MTB{
	meta:
		description = "Trojan:Win32/ProxyChanger.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {50 53 51 56 8b 75 ?? 8b 4d ?? c1 e9 ?? 8b 45 ?? 8b 5d ?? 85 c9 ?? ?? 31 06 01 1e 83 c6 ?? 49 eb ?? 5e 59 5b 58 c9 c2 ?? ?? 72 ?? cb 35 9d } //5
		$a_01_1 = {e5 ec bb e2 f8 35 f3 42 69 7b cb 41 7f 6b 36 1c 42 47 a3 4f ba 9e f5 8b 29 b5 95 b3 0d 12 e7 31 d2 78 4b ea } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}