
rule Trojan_Win32_Bobik_ED_MTB{
	meta:
		description = "Trojan:Win32/Bobik.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 86 cc 00 00 00 2b 46 24 01 46 3c ff 46 48 8b 4e 48 8b 46 64 88 1c 01 b8 ?? ?? ?? ?? 2b 46 44 01 46 68 8b 96 ac 00 00 00 8b ae a0 00 00 00 8b c5 8b 5e 4c 33 c3 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}