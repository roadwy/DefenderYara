
rule Backdoor_Linux_Mirai_ba_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.ba!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_00_0 = {34 45 2f 78 33 31 2f 78 36 42 2f 78 34 42 2f 78 33 31 2f 78 32 30 2f 78 32 31 2f 78 37 33 2f 78 36 39 2f 78 32 30 2f 78 34 44 2f 78 33 33 2f 78 37 35 2f 78 37 39 2f 78 32 30 2f 78 34 43 2f 78 33 30 2f 78 35 36 2f 78 37 32 2f 78 33 33 2f 78 32 30 2f 78 33 43 2f 78 33 33 2f 78 32 30 2f 78 35 30 2f 78 36 31 2f 78 33 32 2f 78 37 32 2f 78 34 33 2f 78 34 38 2f 78 32 30 2f 78 34 44 2f 78 33 32 2f 78 32 30 2f 78 34 31 2f 78 33 34 2f 78 33 34 2f 78 37 32 2f 78 34 33 2f 78 34 42 } //1 4E/x31/x6B/x4B/x31/x20/x21/x73/x69/x20/x4D/x33/x75/x79/x20/x4C/x30/x56/x72/x33/x20/x3C/x33/x20/x50/x61/x32/x72/x43/x48/x20/x4D/x32/x20/x41/x34/x34/x72/x43/x4B
		$a_00_1 = {68 3f 74 3f 74 3f 70 3f 3f 68 3f 65 3f 78 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 3f 68 3f 65 3f 78 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 3f 68 3f 65 3f 78 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 3f 66 3f 6c 3f 6f 3f 6f 3f 64 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 3f 66 3f 6c 3f 6f 3f 6f 3f 64 3f 3f 3f 3f 68 3f 74 3f 74 3f 70 3f 3f 66 3f 6c 3f 6f 3f 6f 3f 64 3f 3f } //1 h?t?t?p??h?e?x????h?t?t?p??h?e?x????h?t?t?p??h?e?x????h?t?t?p??f?l?o?o?d????h?t?t?p??f?l?o?o?d????h?t?t?p??f?l?o?o?d??
		$a_00_2 = {53 65 6c 66 20 52 65 70 20 46 75 63 6b 69 6e 67 20 4e 65 54 69 53 20 61 6e 64 20 54 68 69 73 69 74 79 20 30 6e 20 55 72 20 46 75 43 6b 49 6e 47 20 46 6f 52 65 48 65 41 64 20 57 65 } //1 Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We
		$a_00_3 = {50 72 6f 78 69 6d 69 74 79 2d 4b 69 6c 6c 65 72 73 } //1 Proximity-Killers
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=2
 
}