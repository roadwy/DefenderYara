
rule Ransom_AndroidOS_BlueEagle_A_MTB{
	meta:
		description = "Ransom:AndroidOS/BlueEagle.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_00_0 = {4c 61 6e 64 72 6f 69 64 2f 70 72 6f 76 69 64 65 72 2f 43 61 6c 6c 4c 6f 67 24 43 61 6c 6c 73 } //1 Landroid/provider/CallLog$Calls
		$a_03_1 = {0a 05 2b 05 ?? ?? 00 00 d8 05 06 0a 01 46 01 5a 07 05 01 a0 2b 00 ?? ?? 00 00 98 00 07 08 1a 01 7b 00 07 51 d8 00 00 ff df 04 00 20 32 62 ?? ?? 49 00 01 02 95 05 0b 04 b7 05 d8 0b 0b 01 d8 00 02 01 8e 55 50 05 01 02 01 02 28 f1 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*10) >=11
 
}