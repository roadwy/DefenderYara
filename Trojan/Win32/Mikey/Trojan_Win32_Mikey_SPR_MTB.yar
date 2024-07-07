
rule Trojan_Win32_Mikey_SPR_MTB{
	meta:
		description = "Trojan:Win32/Mikey.SPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {64 6f 77 6e 2e 30 38 31 34 6f 6b 2e 69 6e 66 6f 3a 38 38 38 38 2f 6f 6b 2e 74 78 74 } //2 down.0814ok.info:8888/ok.txt
		$a_81_1 = {64 6f 77 6e 2e 30 38 31 34 6f 6b 2e 69 6e 66 6f } //1 down.0814ok.info
		$a_81_2 = {64 6f 77 6e 31 30 2e 70 64 62 } //1 down10.pdb
		$a_01_3 = {66 00 75 00 63 00 6b 00 79 00 6f 00 75 00 6d 00 6d 00 32 00 5f 00 66 00 69 00 6c 00 74 00 65 00 72 00 } //1 fuckyoumm2_filter
		$a_01_4 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 5f 00 5f 00 74 00 69 00 6d 00 65 00 72 00 65 00 76 00 65 00 6e 00 74 00 20 00 77 00 68 00 65 00 72 00 65 00 20 00 74 00 69 00 6d 00 65 00 72 00 69 00 64 00 3d 00 22 00 66 00 75 00 63 00 6b 00 79 00 6f 00 75 00 6d 00 6d 00 32 00 5f 00 69 00 74 00 69 00 6d 00 65 00 72 00 } //1 select * from __timerevent where timerid="fuckyoumm2_itimer
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}