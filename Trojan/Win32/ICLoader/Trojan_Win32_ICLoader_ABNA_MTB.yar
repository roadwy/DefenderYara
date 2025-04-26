
rule Trojan_Win32_ICLoader_ABNA_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.ABNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 6a ff 68 ?? e4 89 00 68 ?? 7a 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? cc c9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? cc c9 00 c1 e1 08 03 ca 89 0d ?? cc c9 00 c1 e8 10 a3 ?? cc c9 00 6a 01 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}