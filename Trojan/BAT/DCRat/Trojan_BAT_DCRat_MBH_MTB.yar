
rule Trojan_BAT_DCRat_MBH_MTB{
	meta:
		description = "Trojan:BAT/DCRat.MBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe 0c 00 00 fe 0c 01 00 fe 0c 00 00 fe 0c 01 00 93 20 ef 9d 0d 2e 20 36 db 6c 26 61 20 5c bc e6 dc 58 20 ad 91 18 fc 59 20 ca 71 2f e9 61 20 07 00 00 00 62 20 06 00 00 00 63 61 d1 9d } //01 00 
		$a_01_1 = {38 33 38 32 30 34 32 33 36 00 3c 4d 6f 64 75 6c 65 3e 00 74 50 43 6b 46 } //00 00  ㌸㈸㐰㌲6䴼摯汵㹥琀䍐䙫
	condition:
		any of ($a_*)
 
}