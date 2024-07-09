
rule Trojan_Win32_Remcos_MA_MTB{
	meta:
		description = "Trojan:Win32/Remcos.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 ee 04 89 74 24 ?? 31 ff 8b 74 24 ?? 8b 5d ?? 89 f8 c1 e0 ?? 03 44 24 ?? 31 c9 8a 54 0c 20 32 14 0e 88 14 0b 41 83 f9 ?? 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}