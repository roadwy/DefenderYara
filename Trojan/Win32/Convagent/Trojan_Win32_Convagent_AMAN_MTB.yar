
rule Trojan_Win32_Convagent_AMAN_MTB{
	meta:
		description = "Trojan:Win32/Convagent.AMAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 34 88 8b 4a ?? 8b 44 24 ?? 8a 04 01 8b 4c 24 ?? 30 04 0e 8d 4c 24 ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}