
rule Trojan_Win32_DarkGate_MUV_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.MUV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c1 f7 75 e4 8b 45 d0 8a 14 32 32 ?? 01 8b c7 83 7f 14 0f 76 ?? 8b 07 88 14 08 41 8b 45 d4 83 f9 ?? 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}