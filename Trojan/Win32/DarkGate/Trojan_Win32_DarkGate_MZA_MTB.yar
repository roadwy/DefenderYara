
rule Trojan_Win32_DarkGate_MZA_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.MZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce f7 e7 8b c7 2b c2 d1 e8 03 c2 c1 e8 04 03 c0 2b c8 8d 04 cd ?? ?? ?? ?? 2b c1 8d 04 47 8a 44 04 24 32 87 3c 21 6e 00 88 04 2f 47 81 ff 00 d2 16 00 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}