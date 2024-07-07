
rule Trojan_BAT_FormBook_NLY_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {24 39 31 32 65 66 61 39 32 2d 36 31 30 62 2d 34 30 66 32 2d 61 32 38 32 2d 32 32 64 31 62 36 66 36 34 65 30 31 } //1 $912efa92-610b-40f2-a282-22d1b6f64e01
		$a_01_1 = {57 9d a2 29 09 0b 00 00 00 fa 01 33 00 16 00 00 01 } //1
		$a_01_2 = {42 4c 4c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 BLL.Properties.Resources
		$a_81_3 = {70 30 2e 6a 4f } //1 p0.jO
		$a_81_4 = {4c 6f 67 53 77 69 74 63 68 } //1 LogSwitch
		$a_81_5 = {58 43 43 56 56 } //1 XCCVV
		$a_81_6 = {50 61 6e 64 61 } //1 Panda
		$a_01_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_8 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_9 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_10 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_01_11 = {53 48 41 32 35 36 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 } //1 SHA256CryptoServiceProvide
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}