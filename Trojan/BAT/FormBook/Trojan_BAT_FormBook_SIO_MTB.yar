
rule Trojan_BAT_FormBook_SIO_MTB{
	meta:
		description = "Trojan:BAT/FormBook.SIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {3a 2f 2f 61 69 64 65 63 61 2e 6f 72 67 2e 70 65 2f 6d 6a 2f 70 61 6e 65 6c 2f 75 70 6c 6f 61 64 73 2f 47 67 70 61 6f 62 2e 64 61 74 } //1 ://aideca.org.pe/mj/panel/uploads/Ggpaob.dat
		$a_81_1 = {54 6e 6f 71 66 6c 77 74 6c 73 61 2e 6a 70 65 67 } //1 Tnoqflwtlsa.jpeg
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_BAT_FormBook_SIO_MTB_2{
	meta:
		description = "Trojan:BAT/FormBook.SIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_2 = {41 77 61 6b 65 4d 65 74 68 6f 64 } //1 AwakeMethod
		$a_81_3 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_81_4 = {3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 31 32 31 34 34 35 33 35 35 31 31 32 34 37 31 33 35 31 35 2f 31 32 32 32 30 32 38 38 38 37 34 39 32 36 35 37 32 36 32 2f 4c 6e 64 70 6d 72 63 67 65 2e 6d 70 34 } //1 ://cdn.discordapp.com/attachments/1214453551124713515/1222028887492657262/Lndpmrcge.mp4
		$a_81_5 = {53 6d 6a 68 75 74 2e 43 6f 6e 73 75 6d 65 72 73 } //1 Smjhut.Consumers
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}