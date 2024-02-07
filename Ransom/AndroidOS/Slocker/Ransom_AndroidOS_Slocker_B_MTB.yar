
rule Ransom_AndroidOS_Slocker_B_MTB{
	meta:
		description = "Ransom:AndroidOS/Slocker.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 04 00 00 03 00 "
		
	strings :
		$a_00_0 = {41 62 72 61 62 31 36 } //01 00  Abrab16
		$a_00_1 = {61 64 6d 73 75 72 70 72 69 73 65 73 32 } //01 00  admsurprises2
		$a_00_2 = {57 6f 64 6b 54 69 76 61 } //01 00  WodkTiva
		$a_00_3 = {73 65 74 4a 61 76 61 53 63 72 69 70 74 45 6e 61 62 6c 65 64 } //00 00  setJavaScriptEnabled
	condition:
		any of ($a_*)
 
}