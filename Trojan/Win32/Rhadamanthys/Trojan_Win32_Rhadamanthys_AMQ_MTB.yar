
rule Trojan_Win32_Rhadamanthys_AMQ_MTB{
	meta:
		description = "Trojan:Win32/Rhadamanthys.AMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 12 33 14 88 8b 45 ?? 89 10 8b 4d ?? 8b 11 52 8b 4d ?? e8 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 8b 08 89 4d ?? 8b 55 ?? 33 55 ?? 8b 45 ?? 89 10 8b 4d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}