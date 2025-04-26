
rule Ransom_Win32_CryaklCrypt_PD_MTB{
	meta:
		description = "Ransom:Win32/CryaklCrypt.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {61 73 73 68 6f 6c 65 } //1 asshole
		$a_01_1 = {53 48 45 6d 70 74 79 52 65 63 79 63 6c 65 42 69 6e } //1 SHEmptyRecycleBin
		$a_01_2 = {40 74 75 74 61 2e 69 6f } //1 @tuta.io
		$a_01_3 = {62 63 64 65 64 69 74 20 2f 73 65 74 20 7b 64 65 66 61 75 6c 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 4e 6f } //1 bcdedit /set {default} recoveryenabled No
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}