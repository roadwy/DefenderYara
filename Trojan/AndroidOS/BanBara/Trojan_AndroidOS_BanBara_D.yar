
rule Trojan_AndroidOS_BanBara_D{
	meta:
		description = "Trojan:AndroidOS/BanBara.D,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 61 69 74 34 73 65 72 76 69 63 65 4d 65 73 73 65 6e 67 65 72 } //01 00  wait4serviceMessenger
		$a_01_1 = {63 6f 6d 2e 6f 72 63 68 65 73 74 72 61 2e 77 61 74 63 68 64 6f 67 2e 43 32 43 } //01 00  com.orchestra.watchdog.C2C
		$a_01_2 = {48 45 41 44 45 52 5f 41 45 53 5f 4b 45 59 } //01 00  HEADER_AES_KEY
		$a_01_3 = {72 73 61 45 6e 63 6f 64 65 72 } //00 00  rsaEncoder
	condition:
		any of ($a_*)
 
}