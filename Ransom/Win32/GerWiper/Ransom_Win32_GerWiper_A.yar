
rule Ransom_Win32_GerWiper_A{
	meta:
		description = "Ransom:Win32/GerWiper.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0c be 8b d1 c1 ea ?? 88 10 8b d1 c1 ea ?? 88 50 ?? 8b d1 c1 ea ?? 88 50 ?? 88 48 ?? 8b 4e 6c 47 c1 e9 ?? 83 c0 ?? 3b f9 72 d5 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}