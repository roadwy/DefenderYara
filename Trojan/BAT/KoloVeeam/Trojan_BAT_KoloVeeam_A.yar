
rule Trojan_BAT_KoloVeeam_A{
	meta:
		description = "Trojan:BAT/KoloVeeam.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {76 65 65 61 6d } //veeam  1
		$a_80_1 = {64 61 74 61 62 61 73 65 3d 76 65 65 61 6d 62 61 63 6b 75 70 } //database=veeambackup  1
		$a_80_2 = {73 65 6c 65 63 74 20 5b 75 73 65 72 5f 6e 61 6d 65 5d 2c 5b 70 61 73 73 77 6f 72 64 5d 2c 5b 64 65 73 63 72 69 70 74 69 6f 6e 5d 20 66 72 6f 6d 20 5b 76 65 65 61 6d 62 61 63 6b 75 70 5d 2e 5b 64 62 6f 5d 2e 5b 63 72 65 64 65 6e 74 69 61 6c 73 5d } //select [user_name],[password],[description] from [veeambackup].[dbo].[credentials]  1
		$a_80_3 = {65 6e 63 72 79 70 74 65 64 20 70 61 73 73 3a } //encrypted pass:  1
		$a_80_4 = {64 65 63 72 79 70 74 65 64 20 70 61 73 73 3a } //decrypted pass:  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}