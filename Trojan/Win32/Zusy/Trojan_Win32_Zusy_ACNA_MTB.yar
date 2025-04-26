
rule Trojan_Win32_Zusy_ACNA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ACNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a ff 68 ?? 96 63 00 68 ?? 39 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? 28 64 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 28 64 00 c1 e1 08 03 ca 89 0d ?? 28 64 00 c1 e8 10 a3 ?? 28 64 00 33 f6 56 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}