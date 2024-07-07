
rule Trojan_Win64_CoinMiner_RJ{
	meta:
		description = "Trojan:Win64/CoinMiner.RJ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 0f b6 ca 4d 8d 5b 04 41 80 c2 04 45 8d 41 01 41 8d 49 fc 48 63 d1 0f b6 0c 02 41 30 4b fc 41 8d 49 fd 48 63 d1 0f b6 0c 02 41 30 0c 00 41 8d 49 fe 48 63 d1 45 8d 41 02 0f b6 0c 02 41 30 0c 00 41 8d 49 ff 48 63 d1 45 8d 41 03 0f b6 0c 02 41 30 0c 00 41 80 fa 10 72 a6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}