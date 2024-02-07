
rule Trojan_BAT_VenomRAT_FA_MTB{
	meta:
		description = "Trojan:BAT/VenomRAT.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 68 65 63 6b 55 41 43 } //01 00  checkUAC
		$a_01_1 = {56 65 6e 6f 6d 52 41 54 5f 48 56 4e 43 } //01 00  VenomRAT_HVNC
		$a_01_2 = {53 4f 43 4b 53 35 5f 41 55 54 48 5f 4d 45 54 48 4f 44 5f 47 53 53 41 50 49 } //01 00  SOCKS5_AUTH_METHOD_GSSAPI
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 55 52 4c } //01 00  DownloadURL
		$a_01_4 = {67 65 74 5f 48 56 4e 43 5f 46 72 6d 55 52 4c } //00 00  get_HVNC_FrmURL
	condition:
		any of ($a_*)
 
}