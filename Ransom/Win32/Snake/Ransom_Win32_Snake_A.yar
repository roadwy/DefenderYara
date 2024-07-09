
rule Ransom_Win32_Snake_A{
	meta:
		description = "Ransom:Win32/Snake.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {eb 07 96 88 ?? ?? ?? 96 45 39 ?? 7d 18 0f b6 34 2b [0-05] 39 ?? 73 [0-05] 0f b6 3c 29 31 fe [0-06] 72 df eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}