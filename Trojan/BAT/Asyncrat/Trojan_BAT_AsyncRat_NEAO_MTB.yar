
rule Trojan_BAT_AsyncRat_NEAO_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 "
		
	strings :
		$a_01_0 = {31 00 39 00 35 00 2e 00 32 00 2e 00 37 00 39 00 2e 00 32 00 33 00 33 00 } //10 195.2.79.233
		$a_01_1 = {53 79 73 74 65 6d 2e 57 69 6e 64 6f 77 73 2e 46 6f 72 6d 73 } //5 System.Windows.Forms
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e } //1 System.Reflection
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=18
 
}