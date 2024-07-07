
rule Ransom_Win32_Sodinokibi_TA{
	meta:
		description = "Ransom:Win32/Sodinokibi.TA,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 50 0c 83 c2 14 90 02 20 8b 7d 08 81 f7 90 01 04 8b 59 28 6a 2b 58 89 45 fc 0f b7 33 66 85 f6 90 02 10 8d 46 bf 8d 5b 02 66 83 f8 19 77 03 83 ce 20 69 d2 0f 01 00 00 0f b7 c6 0f b7 33 03 d0 66 85 f6 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}