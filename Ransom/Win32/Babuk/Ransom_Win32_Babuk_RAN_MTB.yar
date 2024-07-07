
rule Ransom_Win32_Babuk_RAN_MTB{
	meta:
		description = "Ransom:Win32/Babuk.RAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 6e 65 74 77 6f 72 6b 20 69 73 20 68 61 63 6b 65 64 20 61 6e 64 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 Your network is hacked and files are encrypted
		$a_01_1 = {41 6c 6c 20 64 61 74 61 20 69 73 20 73 74 6f 72 65 64 20 75 6e 74 69 6c 20 79 6f 75 20 77 69 6c 6c 20 70 61 79 } //1 All data is stored until you will pay
		$a_01_2 = {41 66 74 65 72 20 70 61 79 6d 65 6e 74 20 77 65 20 77 69 6c 6c 20 70 72 6f 76 69 64 65 20 79 6f 75 20 74 68 65 20 70 72 6f 67 72 61 6d 73 20 66 6f 72 20 64 65 63 72 79 70 74 69 6f 6e 20 61 6e 64 20 77 65 20 77 69 6c 6c 20 64 65 6c 65 74 65 20 79 6f 75 72 20 64 61 74 61 } //1 After payment we will provide you the programs for decryption and we will delete your data
		$a_01_3 = {59 6f 75 20 77 69 6c 6c 20 66 6f 72 65 76 65 72 20 6c 6f 73 65 20 74 68 65 20 72 65 70 75 74 61 74 69 6f 6e } //1 You will forever lose the reputation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}