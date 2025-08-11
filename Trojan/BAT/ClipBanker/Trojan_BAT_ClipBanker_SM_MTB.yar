
rule Trojan_BAT_ClipBanker_SM_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {06 07 58 0a 00 06 02 fe 04 0d 09 2d b0 } //2
		$a_01_1 = {43 6f 69 6e 43 6c 69 70 70 65 72 } //2 CoinClipper
		$a_01_2 = {63 63 5f 43 6f 6e 66 69 67 2e 65 78 65 } //2 cc_Config.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}