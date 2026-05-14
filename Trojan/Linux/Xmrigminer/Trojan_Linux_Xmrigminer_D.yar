
rule Trojan_Linux_Xmrigminer_D{
	meta:
		description = "Trojan:Linux/Xmrigminer.D,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 6f 00 6c 00 2e 00 68 00 61 00 73 00 68 00 76 00 61 00 75 00 6c 00 74 00 2e 00 70 00 72 00 6f 00 } //10 pool.hashvault.pro
		$a_00_1 = {6d 00 6f 00 6e 00 65 00 72 00 6f 00 2e 00 68 00 65 00 72 00 6f 00 6d 00 69 00 6e 00 65 00 72 00 73 00 2e 00 63 00 6f 00 6d 00 } //10 monero.herominers.com
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10) >=10
 
}