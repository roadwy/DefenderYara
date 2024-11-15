
rule Trojan_Win32_DarkGate_MRT_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.MRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8b 55 e4 8b 4d dc 8b 45 d8 03 ca 42 89 55 ?? 8a 04 08 32 45 ef 88 01 3b 55 08 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}