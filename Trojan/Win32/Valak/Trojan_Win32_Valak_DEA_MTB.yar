
rule Trojan_Win32_Valak_DEA_MTB{
	meta:
		description = "Trojan:Win32/Valak.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b c8 0f b7 f1 8b 44 24 1c 81 c2 ?? ?? ?? ?? 83 44 24 14 04 0f b7 ce 89 55 00 8b 6c 24 20 81 c5 ?? ?? ?? ?? 8d 04 41 03 c7 8d 04 41 03 e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}