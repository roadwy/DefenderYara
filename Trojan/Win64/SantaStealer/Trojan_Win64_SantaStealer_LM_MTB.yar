
rule Trojan_Win64_SantaStealer_LM_MTB{
	meta:
		description = "Trojan:Win64/SantaStealer.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 03 83 f2 01 88 14 01 48 83 c0 01 4c 39 c0 75 ?? 4d 63 c9 48 89 c8 42 c6 04 09 00 48 83 c4 20 } //20
		$a_81_1 = {74 2e 6d 65 2f 53 61 6e 74 61 53 74 65 61 6c 65 72 } //15 t.me/SantaStealer
		$a_81_2 = {43 68 72 6f 6d 65 45 6c 65 76 61 74 6f 72 5f 47 65 74 45 6e 63 72 79 70 74 65 64 42 6c 6f 62 } //5 ChromeElevator_GetEncryptedBlob
		$a_81_3 = {43 68 72 6f 6d 65 45 6c 65 76 61 74 6f 72 5f 43 6c 65 61 6e 75 70 } //3 ChromeElevator_Cleanup
		$a_81_4 = {63 72 79 70 74 6f 63 75 72 72 65 6e 63 79 } //2 cryptocurrency
	condition:
		((#a_03_0  & 1)*20+(#a_81_1  & 1)*15+(#a_81_2  & 1)*5+(#a_81_3  & 1)*3+(#a_81_4  & 1)*2) >=45
 
}