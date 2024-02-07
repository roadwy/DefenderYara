
rule Trojan_AndroidOS_Fakewallet_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Fakewallet.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 6f 73 69 6e 66 6f 2e 6d 79 74 6f 6b 65 6e 70 6f 63 6b 65 74 2e 76 69 70 } //01 00  bosinfo.mytokenpocket.vip
		$a_00_1 = {63 6f 6d 2f 74 6f 6b 65 6e 62 61 6e 6b 2f 61 63 74 69 76 69 74 79 2f 73 70 6c 61 73 68 } //01 00  com/tokenbank/activity/splash
		$a_00_2 = {2f 76 31 2f 69 6e 66 6f 2f 67 65 74 5f 70 65 72 6d 69 73 73 69 6f 6e } //01 00  /v1/info/get_permission
		$a_00_3 = {62 74 63 2d 77 61 6c 6c 65 74 2f 73 65 67 77 69 74 } //00 00  btc-wallet/segwit
	condition:
		any of ($a_*)
 
}