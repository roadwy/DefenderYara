
rule Ransom_Win32_Prestige_B{
	meta:
		description = "Ransom:Win32/Prestige.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 2d 2d 2d 2d 45 4e 44 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d 0a 00 00 00 ?? 00 50 00 72 00 65 00 73 00 74 00 69 00 67 00 65 00 2e 00 72 00 61 00 6e 00 75 00 73 00 6f 00 6d 00 65 00 77 00 61 00 72 00 65 00 40 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}