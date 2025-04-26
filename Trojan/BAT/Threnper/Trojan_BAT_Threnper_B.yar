
rule Trojan_BAT_Threnper_B{
	meta:
		description = "Trojan:BAT/Threnper.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 00 75 00 20 00 73 00 74 00 65 00 76 00 65 00 5f 00 75 00 6b 00 40 00 73 00 61 00 66 00 65 00 2d 00 6d 00 61 00 69 00 6c 00 2e 00 6e 00 65 00 74 00 5f 00 73 00 65 00 72 00 76 00 } //4 -u steve_uk@safe-mail.net_serv
		$a_01_1 = {2d 00 6f 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 70 00 6f 00 6f 00 6c 00 2e 00 35 00 30 00 62 00 74 00 63 00 2e 00 63 00 6f 00 6d 00 3a 00 38 00 33 00 33 00 32 00 } //1 -o http://pool.50btc.com:8332
		$a_01_2 = {73 00 63 00 76 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 scvhost.exe
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}