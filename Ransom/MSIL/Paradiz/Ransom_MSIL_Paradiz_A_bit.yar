
rule Ransom_MSIL_Paradiz_A_bit{
	meta:
		description = "Ransom:MSIL/Paradiz.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3c 00 52 00 53 00 41 00 4b 00 65 00 79 00 56 00 61 00 6c 00 75 00 65 00 3e 00 } //1 <RSAKeyValue>
		$a_01_1 = {2f 00 61 00 70 00 69 00 2f 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 70 00 68 00 70 00 } //1 /api/Encrypted.php
		$a_01_2 = {76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 } //1 vssadmin delete shadows /all
		$a_01_3 = {2a 00 2e 00 70 00 61 00 72 00 61 00 64 00 69 00 73 00 65 00 } //1 *.paradise
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}