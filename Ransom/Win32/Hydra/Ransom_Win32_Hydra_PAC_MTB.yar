
rule Ransom_Win32_Hydra_PAC_MTB{
	meta:
		description = "Ransom:Win32/Hydra.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 20 68 61 76 65 20 62 65 65 6e 20 6b 69 63 6b 65 64 20 66 72 6f 6d 20 74 68 65 20 74 65 61 6d 20 21 21 } //1 You have been kicked from the team !!
		$a_01_1 = {4c 6f 63 61 6c 5c 24 68 59 64 72 34 52 61 6e 73 24 } //1 Local\$hYdr4Rans$
		$a_81_2 = {23 46 49 4c 45 53 45 4e 43 52 59 50 54 45 44 2e 74 78 74 } //1 #FILESENCRYPTED.txt
		$a_81_3 = {61 61 61 5f 54 6f 75 63 68 4d 65 4e 6f 74 5f 2e 74 78 74 } //1 aaa_TouchMeNot_.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}