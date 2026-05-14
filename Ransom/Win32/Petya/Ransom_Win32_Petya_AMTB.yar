
rule Ransom_Win32_Petya_AMTB{
	meta:
		description = "Ransom:Win32/Petya!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 41 56 45 41 53 53 4b 59 3a 20 59 6f 75 72 20 64 72 69 76 65 20 69 73 20 6c 6f 63 6b 65 64 2e 20 53 65 6e 64 20 42 54 43 20 74 6f 20 75 6e 6c 6f 63 6b 2e } //SAVEASSKY: Your drive is locked. Send BTC to unlock.  1
		$a_80_1 = {53 41 56 45 41 53 53 4b 59 20 52 41 4e 53 4f 4d } //SAVEASSKY RANSOM  1
		$a_80_2 = {59 6f 75 20 62 65 63 61 6d 65 20 76 69 63 74 69 6d 20 6f 66 20 74 68 65 20 53 41 56 45 41 53 53 4b 59 20 52 41 4e 53 4f 4d 57 41 52 45 } //You became victim of the SAVEASSKY RANSOMWARE  1
		$a_80_3 = {54 68 65 72 65 20 69 73 20 6e 6f 20 77 61 79 20 74 6f 20 72 65 73 74 6f 72 65 20 79 6f 75 72 20 64 61 74 61 20 77 69 74 68 6f 75 74 20 61 20 73 70 65 63 69 61 6c 20 6b 65 79 2e } //There is no way to restore your data without a special key.  1
		$a_80_4 = {68 74 74 70 3a 2f 2f 70 65 74 79 61 33 6a 78 66 70 32 74 37 67 33 69 2e 6f 6e 69 6f 6e 2f 4f 4e 31 7a 37 7a } //http://petya3jxfp2t7g3i.onion/ON1z7z  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}