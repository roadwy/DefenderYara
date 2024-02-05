
rule Ransom_Win32_Nemty_C{
	meta:
		description = "Ransom:Win32/Nemty.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {c7 44 24 10 90 01 04 b8 90 01 04 81 44 24 10 90 01 04 81 44 24 10 90 01 04 81 e3 72 bf b9 21 81 6c 24 10 90 01 04 81 44 24 10 90 01 04 b8 00 b4 f7 0d 81 44 24 10 90 01 04 c1 e8 07 81 44 24 10 90 01 04 c1 e0 18 25 90 01 04 83 44 24 10 02 8b 44 24 10 0f af c6 8d 0c 85 90 01 04 03 cd e8 90 01 04 46 3b f7 72 8e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}