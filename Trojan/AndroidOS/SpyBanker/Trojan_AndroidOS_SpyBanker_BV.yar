
rule Trojan_AndroidOS_SpyBanker_BV{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.BV,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {26 74 65 78 74 3d f0 9d 97 95 f0 9d 97 b2 f0 9d 97 bf f0 9d 97 b5 f0 9d 97 ae f0 9d 98 80 f0 9d 97 b6 f0 9d 97 b9 20 f0 9d 97 a7 f0 9d 97 b2 f0 9d 97 bf f0 9d 97 b8 f0 9d 97 bc f0 9d 97 bb f0 9d 97 b2 f0 9d 97 b8 f0 9d 98 80 f0 9d 97 b6 } //02 00 
		$a_01_1 = {61 70 70 6a 61 76 61 2f 52 65 63 65 69 76 65 53 6d 73 } //02 00  appjava/ReceiveSms
		$a_01_2 = {26 74 65 78 74 3d 44 69 74 6f 6c 61 6b } //00 00  &text=Ditolak
	condition:
		any of ($a_*)
 
}