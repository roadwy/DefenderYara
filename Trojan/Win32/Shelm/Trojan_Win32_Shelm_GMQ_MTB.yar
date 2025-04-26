
rule Trojan_Win32_Shelm_GMQ_MTB{
	meta:
		description = "Trojan:Win32/Shelm.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 10 2b 45 f4 c7 44 24 ?? ?? ?? ?? ?? 89 44 24 08 8b 45 f0 89 44 24 04 8b 45 08 89 04 24 e8 ?? ?? ?? ?? 83 ec 10 89 45 ec 8b 45 ec 01 45 f0 8b 45 ec 01 45 f4 83 7d ec ff ?? ?? c7 44 24 ?? 6e 50 40 00 8b 45 08 89 04 24 } //10
		$a_01_1 = {64 7a 33 2e 64 64 6e 73 2e 6e 65 74 } //1 dz3.ddns.net
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}