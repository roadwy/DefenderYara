
rule Trojan_BAT_Formbook_BA_MTB{
	meta:
		description = "Trojan:BAT/Formbook.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {95 58 20 ff 00 00 00 5f 13 0d 09 11 05 07 11 05 91 11 04 11 0d 95 61 28 ?? 00 00 0a 9c 11 05 17 58 13 05 00 11 05 6e 09 8e 69 6a fe 04 } //4
		$a_03_1 = {0a 0c 07 8e 69 8d ?? 00 00 01 0d 20 00 01 00 00 8d ?? 00 00 01 13 04 16 13 05 2b 0f } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}