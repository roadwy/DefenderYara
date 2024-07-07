
rule Ransom_Win32_GerWiper_A{
	meta:
		description = "Ransom:Win32/GerWiper.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0c be 8b d1 c1 ea 90 01 01 88 10 8b d1 c1 ea 90 01 01 88 50 90 01 01 8b d1 c1 ea 90 01 01 88 50 90 01 01 88 48 90 01 01 8b 4e 6c 47 c1 e9 90 01 01 83 c0 90 01 01 3b f9 72 d5 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}