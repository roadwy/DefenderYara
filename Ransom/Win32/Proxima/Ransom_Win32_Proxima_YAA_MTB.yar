
rule Ransom_Win32_Proxima_YAA_MTB{
	meta:
		description = "Ransom:Win32/Proxima.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {0a c8 88 0e 0f b6 47 01 0f b6 88 90 01 04 0f b6 47 02 c0 e1 04 0f b6 80 90 01 04 c0 e8 02 0a c8 88 4e 01 0f b6 47 02 0f b6 4f 03 83 c7 04 0f b6 80 90 01 04 c0 e0 06 0a 81 90 01 04 88 46 02 83 c6 03 90 00 } //1
		$a_01_1 = {73 69 6c 65 6e 74 5f 65 6e 63 72 79 70 74 69 6f 6e } //1 silent_encryption
		$a_01_2 = {65 6e 63 72 79 70 74 5f 66 69 6c 65 6e 61 6d 65 } //1 encrypt_filename
		$a_01_3 = {77 69 70 65 5f 72 65 63 79 63 6c 65 62 69 6e } //1 wipe_recyclebin
		$a_01_4 = {6b 69 6c 6c 5f 64 65 66 65 6e 64 65 72 } //1 kill_defender
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}