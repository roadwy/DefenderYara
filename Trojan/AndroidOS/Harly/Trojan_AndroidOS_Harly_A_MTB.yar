
rule Trojan_AndroidOS_Harly_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Harly.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {1a 05 1a 53 71 20 0a 08 35 00 0c 05 38 00 07 00 6e 10 0f 03 00 00 0c 00 28 1c 1a 00 7d 6c 71 10 49 80 00 00 0c 00 71 10 d6 07 00 00 0a 06 38 06 03 00 28 0c 22 06 7e 19 70 20 17 7e 06 00 6e 10 20 7e 06 00 0a 00 39 00 04 00 07 40 28 02 07 60 39 00 03 00 28 64 22 06 7e 19 22 07 df 19 70 10 2a 80 07 00 71 00 47 80 00 00 0b 08 6e 30 32 80 87 09 1a 08 28 08 6e 20 36 80 87 00 6e 10 43 80 07 00 0c 07 70 30 16 7e 06 07 } //2
		$a_00_1 = {73 65 70 2e 74 6f 70 73 61 76 6f 72 2e 73 69 74 65 } //2 sep.topsavor.site
		$a_00_2 = {70 65 72 73 69 73 74 65 64 69 6e 73 74 61 6c 6c 61 74 69 6f 6e } //1 persistedinstallation
		$a_00_3 = {63 6f 6d 2f 62 61 72 62 61 72 61 68 65 6e 72 69 65 74 74 61 2f 6c 69 76 65 77 61 6c 6c 70 61 70 65 72 } //1 com/barbarahenrietta/livewallpaper
		$a_00_4 = {69 73 65 6d 75 6c 61 74 6f 72 } //1 isemulator
		$a_00_5 = {67 65 74 41 70 70 6c 69 63 61 74 69 6f 6e 41 75 74 6f 53 74 61 72 74 } //1 getApplicationAutoStart
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}