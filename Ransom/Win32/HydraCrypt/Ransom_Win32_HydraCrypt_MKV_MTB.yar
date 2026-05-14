
rule Ransom_Win32_HydraCrypt_MKV_MTB{
	meta:
		description = "Ransom:Win32/HydraCrypt.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 8a 1c 06 02 d3 88 55 0b 0f b6 d2 0f b6 0c 02 88 0c 06 88 1c 02 0f b6 14 06 0f b6 cb 03 d1 81 e2 ff 00 00 00 0f b6 0c 02 8b 55 fc 30 4c 17 ff 8a 55 0b 3b 7d f8 72 } //5
		$a_01_1 = {41 74 74 65 6e 74 69 6f 6e 21 20 41 6c 6c 20 59 6f 75 72 20 64 61 74 61 20 77 61 73 20 65 6e 63 72 79 70 74 65 64 21 } //1 Attention! All Your data was encrypted!
		$a_01_2 = {4d 41 59 20 44 41 4d 41 47 45 20 59 4f 55 52 20 44 41 54 41 20 46 4f 52 45 56 45 52 21 } //1 MAY DAMAGE YOUR DATA FOREVER!
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}