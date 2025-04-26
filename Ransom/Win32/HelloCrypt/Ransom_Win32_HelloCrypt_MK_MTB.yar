
rule Ransom_Win32_HelloCrypt_MK_MTB{
	meta:
		description = "Ransom:Win32/HelloCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {24 52 65 63 79 63 6c 65 2e 42 69 6e } //1 $Recycle.Bin
		$a_81_1 = {5c 48 65 6c 6c 6f 2e 74 78 74 } //1 \Hello.txt
		$a_81_2 = {41 6c 6c 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 All files are encrypted
		$a_81_3 = {64 65 63 72 79 70 74 69 6f 6e 20 63 6f 73 74 20 77 69 6c 6c 20 62 65 20 61 75 74 6f 6d 61 74 69 63 61 6c 6c 79 20 69 6e 63 72 65 61 73 65 64 } //1 decryption cost will be automatically increased
		$a_81_4 = {79 6f 75 72 20 70 65 72 73 6f 6e 61 6c 20 69 64 3a } //1 your personal id:
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}