
rule Ransom_MSIL_Fantomcrypt_A{
	meta:
		description = "Ransom:MSIL/Fantomcrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {63 72 69 74 69 63 61 6c 20 75 70 64 61 74 65 20 6b 62 30 31 } //2 critical update kb01
		$a_00_1 = {63 72 69 74 69 63 61 6c 75 70 64 61 74 65 30 31 } //1 criticalupdate01
		$a_01_2 = {66 74 20 20 63 6f 72 70 6f 72 61 74 69 6f 6e } //1 ft  corporation
		$a_00_3 = {63 72 69 74 69 63 61 6c 20 75 70 64 61 74 65 } //1 critical update
		$a_00_4 = {6c 6f 63 6b 64 69 72 } //1 lockdir
		$a_00_5 = {70 61 73 73 77 6f 72 64 } //1 password
		$a_00_6 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_00_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=7
 
}