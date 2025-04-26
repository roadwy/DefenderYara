
rule Trojan_Win64_Lazy_AMCW_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AMCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 c0 40 00 00 10 00 00 00 4e 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 a0 ae 00 00 00 d0 40 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Lazy_AMCW_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.AMCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 55 48 8b ec 48 83 ec 50 c7 45 d0 ?? ?? ?? ?? 33 c0 c7 45 d4 ?? ?? ?? ?? ba ?? ?? ?? ?? c7 45 d8 ?? ?? ?? ?? c7 45 dc [0-35] c6 45 fc 01 8d 0c 02 66 31 4c 45 d0 48 ff c0 48 83 f8 15 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}