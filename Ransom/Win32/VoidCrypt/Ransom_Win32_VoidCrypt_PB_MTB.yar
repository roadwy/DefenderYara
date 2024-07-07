
rule Ransom_Win32_VoidCrypt_PB_MTB{
	meta:
		description = "Ransom:Win32/VoidCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 2d 00 6d 00 65 00 2e 00 74 00 78 00 74 00 } //1 \Decrypt-me.txt
		$a_01_1 = {2e 53 6f 70 68 6f 73 } //1 .Sophos
		$a_01_2 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //1 wbadmin delete catalog -quiet
		$a_01_3 = {41 00 6c 00 6c 00 20 00 59 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 48 00 61 00 73 00 20 00 42 00 65 00 65 00 6e 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 All Your Files Has Been Encrypted
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}