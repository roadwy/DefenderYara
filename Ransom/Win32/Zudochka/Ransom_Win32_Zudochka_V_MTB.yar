
rule Ransom_Win32_Zudochka_V_MTB{
	meta:
		description = "Ransom:Win32/Zudochka.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 45 ec 8b 55 ec 89 15 90 01 04 a1 90 01 04 a3 90 01 04 8b 0d 90 01 04 81 c1 c0 0f 08 00 89 0d 90 01 04 8b 45 ec 8b e5 90 00 } //02 00 
		$a_03_1 = {8b 11 89 15 90 01 04 a1 90 01 04 83 e8 90 01 01 a3 90 01 04 8b 15 90 01 04 83 c2 90 01 01 ff 35 90 01 04 8f 45 90 01 01 8b ca 31 4d 90 01 01 8b 45 90 01 01 c7 05 90 02 0a 01 05 90 01 04 8b 0d 90 01 04 8b 15 90 01 04 89 11 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}