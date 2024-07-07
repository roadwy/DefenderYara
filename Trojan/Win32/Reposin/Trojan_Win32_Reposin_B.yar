
rule Trojan_Win32_Reposin_B{
	meta:
		description = "Trojan:Win32/Reposin.B,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 7d 08 05 89 45 14 75 46 85 c0 75 42 56 8b f3 57 85 f6 74 29 66 83 7e 38 00 74 22 a1 04 40 00 10 3b 46 44 74 0c 8b 7e 3c e8 83 ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}