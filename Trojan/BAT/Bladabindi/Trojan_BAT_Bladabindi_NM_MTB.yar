
rule Trojan_BAT_Bladabindi_NM_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 11 4b 11 05 4b 61 ?? ?? ?? ?? 00 5f 16 fe 01 } //5
		$a_03_1 = {13 0f 11 0f 1f 0c 64 11 0f 61 ?? ?? 0f 00 00 5f 13 0c 11 06 11 0c } //5
		$a_81_2 = {65 62 33 63 39 39 61 65 2d 34 61 62 30 2d 34 30 34 33 2d 39 62 64 30 2d 32 66 62 63 62 65 64 30 32 66 64 64 } //1 eb3c99ae-4ab0-4043-9bd0-2fbcbed02fdd
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_81_2  & 1)*1) >=11
 
}