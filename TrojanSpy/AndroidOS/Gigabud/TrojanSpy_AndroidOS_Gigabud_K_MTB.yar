
rule TrojanSpy_AndroidOS_Gigabud_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Gigabud.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {21 32 35 21 0c 00 48 02 03 01 df 02 02 69 8d 22 4f 02 03 01 d8 01 01 01 28 f4 } //1
		$a_00_1 = {42 61 6e 6b 43 61 72 64 49 6e 66 6f } //1 BankCardInfo
		$a_00_2 = {77 72 69 74 65 56 69 64 65 6f 55 72 6c } //1 writeVideoUrl
		$a_00_3 = {78 2f 75 73 65 72 2d 62 61 6e 6b 2d 70 77 64 } //1 x/user-bank-pwd
		$a_00_4 = {65 78 65 63 75 74 65 20 63 6f 6d 6d 61 6e 64 } //1 execute command
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}