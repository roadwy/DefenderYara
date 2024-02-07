
rule DDoS_Linux_SAgnt_B_xp{
	meta:
		description = "DDoS:Linux/SAgnt.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 6b 65 74 20 4f 6c 75 73 74 75 72 6d 61 20 48 61 74 61 73 69 25 73 } //01 00  Soket Olusturma Hatasi%s
		$a_01_1 = {53 65 74 20 68 61 74 61 20 2e 2e 2e 25 64 } //01 00  Set hata ...%d
		$a_01_2 = {69 73 61 72 65 74 3a 20 25 64 } //01 00  isaret: %d
		$a_01_3 = {4f 72 74 61 6c 61 6d 61 20 70 61 6b 65 74 20 2f 20 73 61 6e 69 79 65 3a 20 25 64 } //01 00  Ortalama paket / saniye: %d
		$a_01_4 = {50 6f 72 74 20 48 61 74 61 73 69 } //00 00  Port Hatasi
	condition:
		any of ($a_*)
 
}