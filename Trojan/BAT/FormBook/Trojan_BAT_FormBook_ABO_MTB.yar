
rule Trojan_BAT_FormBook_ABO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.ABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0a 16 0b 2b 0f 00 06 07 58 02 03 07 58 91 52 00 07 17 58 0b 07 05 fe 04 0c 08 2d e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_FormBook_ABO_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.ABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0b 2b 36 06 07 28 ?? 00 00 06 16 0c 2b 15 07 08 28 ?? 00 00 06 02 07 08 03 04 28 ?? 00 00 06 08 17 58 0c 08 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 d9 } //3
		$a_03_1 = {0a 02 03 04 6f ?? 00 00 0a 0e 04 05 6f ?? 00 00 0a 59 0b 06 28 ?? 00 00 06 07 05 28 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}
rule Trojan_BAT_FormBook_ABO_MTB_3{
	meta:
		description = "Trojan:BAT/FormBook.ABO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {38 46 36 44 44 30 33 33 32 35 36 41 41 44 38 46 34 39 30 37 36 45 38 32 41 30 33 35 46 30 33 35 46 31 46 44 30 33 44 46 42 41 46 43 41 39 42 46 33 34 46 33 35 46 32 30 31 30 35 32 44 42 39 35 } //1 8F6DD033256AAD8F49076E82A035F035F1FD03DFBAFCA9BF34F35F201052DB95
		$a_01_1 = {43 6f 6e 76 65 72 74 50 72 6f 76 69 64 65 72 2e 43 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e 46 6f 72 6d } //1 ConvertProvider.CommunicationForm
		$a_01_2 = {63 33 37 31 36 31 35 38 2d 65 34 34 64 2d 34 31 65 61 2d 61 39 37 38 2d 37 62 39 33 32 39 34 34 64 36 34 30 } //1 c3716158-e44d-41ea-a978-7b932944d640
		$a_01_3 = {43 6f 6e 76 65 72 74 50 72 6f 76 69 64 65 72 2e 50 72 6f 74 6f 63 6f 6c 43 6f 6e 66 69 67 46 6f 72 6d } //1 ConvertProvider.ProtocolConfigForm
		$a_01_4 = {34 4f 42 35 34 41 4b 35 38 46 35 35 46 37 52 35 37 37 52 52 38 34 } //1 4OB54AK58F55F7R577RR84
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}