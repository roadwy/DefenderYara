
rule Trojan_Win32_RisePro_DB_{
	meta:
		description = "Trojan:Win32/RisePro.DB!!Risepro.gen!MTB,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {54 65 6c 65 67 72 61 6d 3a 20 68 74 74 70 73 3a 2f 2f 74 2e 6d 65 2f 52 69 73 65 50 72 6f 53 55 50 50 4f 52 54 } //01 00  Telegram: https://t.me/RiseProSUPPORT
		$a_81_1 = {69 70 69 6e 66 6f 2e 69 6f } //01 00  ipinfo.io
		$a_81_2 = {6d 61 78 6d 69 6e 64 2e 63 6f 6d 2f 65 6e 2f 6c 6f 63 61 74 65 2d 6d 79 2d 69 70 2d 61 64 64 72 65 73 73 } //00 00  maxmind.com/en/locate-my-ip-address
	condition:
		any of ($a_*)
 
}