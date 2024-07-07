
rule TrojanDropper_AndroidOS_Banker_AD_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Banker.AD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 6d 77 69 61 75 65 68 6a 6c 6a 63 4d 47 56 6c 4f 54 64 6a 4f 44 55 79 4d 54 51 32 4d 44 5a 6c 4d 44 49 31 } //1 pmwiauehjljcMGVlOTdjODUyMTQ2MDZlMDI1
		$a_00_1 = {6f 6c 63 62 6c 69 67 65 6a 6a 61 7a 4f 54 67 35 4d 44 59 7a 59 54 67 33 5a 54 55 30 4f 44 41 35 59 6d 52 69 4d 6a 6b 35 5a 47 55 32 59 32 49 30 4d 54 6c 69 4f 44 45 78 4d 6a 41 7a 4e 32 49 35 4e 32 4a 6d 5a 6d 55 77 4f 47 59 7a } //1 olcbligejjazOTg5MDYzYTg3ZTU0ODA5YmRiMjk5ZGU2Y2I0MTliODExMjAzN2I5N2JmZmUwOGYz
		$a_00_2 = {63 7a 68 70 64 79 63 68 62 62 7a 6e 4e 44 63 31 59 6a 52 6a 4e 6a 5a 68 4e 6d 46 6c 5a 57 4e 6b 4d 54 55 30 4d 44 67 79 4d 6a 42 69 4d 57 49 35 59 54 6b 79 4d 6d 5a 6d 4d 44 45 31 4f 57 45 7a 4e 47 5a 6d 59 7a 4a 6b 4d 7a 67 34 4d 57 55 34 4f 51 3d 3d } //1 czhpdychbbznNDc1YjRjNjZhNmFlZWNkMTU0MDgyMjBiMWI5YTkyMmZmMDE1OWEzNGZmYzJkMzg4MWU4OQ==
		$a_00_3 = {65 72 7a 67 64 75 70 6c 62 72 6b 74 5a 44 49 7a 5a 47 4d 35 5a 57 49 77 4d 6a 4d 35 4e 6a 46 6b 59 57 45 78 59 57 51 3d } //1 erzgduplbrktZDIzZGM5ZWIwMjM5NjFkYWExYWQ=
		$a_00_4 = {76 67 72 65 71 66 72 76 71 70 63 6f 59 57 52 6c 5a 54 4d 77 4e 7a 56 6d 4d 44 63 31 59 54 49 78 4d 32 4a 68 } //1 vgreqfrvqpcoYWRlZTMwNzVmMDc1YTIxM2Jh
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}