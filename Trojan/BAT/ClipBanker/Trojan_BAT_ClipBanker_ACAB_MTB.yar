
rule Trojan_BAT_ClipBanker_ACAB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ACAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 06 7e 44 00 00 04 06 28 ?? 01 00 06 28 ?? 01 00 06 28 ?? 01 00 06 9d 08 17 13 04 1f fd 20 73 dc 05 4a 20 4f ?? db 25 61 20 3c 4c de 6f 33 0a 18 13 04 fe 1c 0d 00 00 1b 58 00 58 0c 08 02 32 be } //4
		$a_01_1 = {49 4c 6f 76 65 59 6f 75 72 4d 6f 74 68 65 72 } //2 ILoveYourMother
		$a_01_2 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 } //1 Confuser.Core
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=7
 
}