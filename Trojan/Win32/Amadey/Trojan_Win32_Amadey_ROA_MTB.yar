
rule Trojan_Win32_Amadey_ROA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.ROA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c1 3b f0 0f 84 ?? ?? ?? ?? 8b 45 e4 8d 4d c0 6a 01 c7 45 d0 00 00 00 00 c7 45 d4 0f 00 00 00 8a 04 30 32 06 88 45 eb 8d 45 eb 50 c6 45 c0 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}