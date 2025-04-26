
rule Trojan_BAT_ClipBanker_B_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 33 62 61 35 33 65 39 38 2d 66 61 39 39 2d 34 32 61 31 2d 38 61 33 61 2d 36 62 61 35 38 34 62 35 61 32 33 63 } //1 $3ba53e98-fa99-42a1-8a3a-6ba584b5a23c
		$a_81_1 = {73 65 74 5f 52 65 67 69 73 74 72 79 4e 61 6d 65 } //1 set_RegistryName
		$a_81_2 = {43 6c 69 70 62 6f 61 72 64 4e 6f 74 69 66 69 63 61 74 69 6f 6e } //1 ClipboardNotification
		$a_81_3 = {4b 56 4c 43 20 6d 65 64 69 61 20 70 6c 61 79 65 72 } //1 KVLC media player
		$a_01_4 = {73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //1 shell.exe
		$a_01_5 = {33 00 2e 00 32 00 2e 00 33 00 2e 00 32 00 } //1 3.2.3.2
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}