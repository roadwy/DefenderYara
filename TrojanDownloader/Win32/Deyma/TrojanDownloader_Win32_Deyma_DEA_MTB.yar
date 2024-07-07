
rule TrojanDownloader_Win32_Deyma_DEA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Deyma.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0a 00 00 "
		
	strings :
		$a_81_0 = {34 33 35 30 69 6a 79 33 30 75 39 34 35 6a 39 66 } //1 4350ijy30u945j9f
		$a_81_1 = {6d 4b 41 4f 44 5a 42 42 4c 42 } //1 mKAODZBBLB
		$a_81_2 = {5a 6d 4c 59 66 4e 5a 73 59 47 } //1 ZmLYfNZsYG
		$a_81_3 = {6e 58 49 49 71 76 54 5a 57 51 } //1 nXIIqvTZWQ
		$a_81_4 = {78 49 71 68 45 64 62 55 4f 76 } //1 xIqhEdbUOv
		$a_81_5 = {77 50 6e 72 41 49 79 4f 70 65 } //1 wPnrAIyOpe
		$a_81_6 = {70 69 51 6b 41 71 72 46 79 51 } //1 piQkAqrFyQ
		$a_81_7 = {6c 54 45 45 7a 47 76 53 62 41 } //1 lTEEzGvSbA
		$a_81_8 = {4f 46 46 50 71 73 6f 58 4f 65 } //1 OFFPqsoXOe
		$a_81_9 = {49 6f 63 57 56 79 59 72 66 6b } //1 IocWVyYrfk
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=3
 
}