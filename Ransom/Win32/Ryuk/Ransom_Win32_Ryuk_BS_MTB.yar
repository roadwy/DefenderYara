
rule Ransom_Win32_Ryuk_BS_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 ff 15 90 01 04 8b 44 24 90 01 01 6a 23 33 d2 5b 8d 0c 06 8b c6 f7 f3 8b 44 24 90 01 01 8a 04 02 30 01 46 3b 74 24 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}