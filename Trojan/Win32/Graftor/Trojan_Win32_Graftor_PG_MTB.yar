
rule Trojan_Win32_Graftor_PG_MTB{
	meta:
		description = "Trojan:Win32/Graftor.PG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d6 8b c8 33 d2 8b c3 f7 f1 8b 45 ?? 8b 4d ?? 03 c3 43 8a 92 ?? ?? ?? ?? 32 14 01 88 10 83 fb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}