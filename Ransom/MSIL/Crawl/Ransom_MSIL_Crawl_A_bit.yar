
rule Ransom_MSIL_Crawl_A_bit{
	meta:
		description = "Ransom:MSIL/Crawl.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 00 6f 00 75 00 72 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //01 00  Your system files has been encrypted
		$a_01_1 = {79 00 6f 00 75 00 72 00 5f 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 5f 00 70 00 75 00 62 00 6c 00 69 00 63 00 5f 00 6b 00 65 00 79 00 2e 00 72 00 6b 00 66 00 } //01 00  your_encryption_public_key.rkf
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 73 00 69 00 67 00 6d 00 61 00 6c 00 61 00 62 00 2e 00 6c 00 76 00 2f 00 6f 00 74 00 68 00 65 00 72 00 2f 00 63 00 72 00 79 00 70 00 74 00 2f 00 } //01 00  http://sigmalab.lv/other/crypt/
		$a_01_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 63 00 72 00 61 00 77 00 6c 00 } //00 00  SOFTWARE\crawl
	condition:
		any of ($a_*)
 
}