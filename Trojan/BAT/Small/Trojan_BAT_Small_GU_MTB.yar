
rule Trojan_BAT_Small_GU_MTB{
	meta:
		description = "Trojan:BAT/Small.GU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 09 00 00 "
		
	strings :
		$a_80_0 = {72 4e 4c 69 33 78 54 73 6f 4c 72 35 56 45 42 6d 45 6f 37 51 58 69 65 6a 75 7a 4f 32 32 42 52 38 54 45 38 76 44 63 4b 58 63 4a 78 76 76 58 57 4e 6c 34 66 55 62 73 71 37 45 68 49 4d 37 4f 4e 4d 53 52 70 6c 4c 6d 69 } //rNLi3xTsoLr5VEBmEo7QXiejuzO22BR8TE8vDcKXcJxvvXWNl4fUbsq7EhIM7ONMSRplLmi  3
		$a_80_1 = {4a 72 78 61 4c 73 6f 77 72 72 59 56 50 4b 46 45 30 46 } //JrxaLsowrrYVPKFE0F  3
		$a_80_2 = {70 52 63 6f 61 50 38 7a 70 4e 32 32 52 44 31 79 76 37 39 66 4f 5a 4c 4c 37 48 73 35 74 5a 78 35 70 37 39 55 49 61 30 33 32 67 79 79 69 57 78 46 78 39 4d 48 6b 74 78 4d 4c 79 59 } //pRcoaP8zpN22RD1yv79fOZLL7Hs5tZx5p79UIa032gyyiWxFx9MHktxMLyY  3
		$a_80_3 = {68 58 65 55 4f 4c 44 63 36 39 74 68 77 6e 6a 51 4e 63 6b 77 7a 62 35 68 50 57 68 59 42 58 37 43 41 6a 6f 45 72 } //hXeUOLDc69thwnjQNckwzb5hPWhYBX7CAjoEr  3
		$a_80_4 = {6b 74 71 37 79 44 65 78 79 79 35 69 49 37 39 30 49 } //ktq7yDexyy5iI790I  3
		$a_80_5 = {47 65 74 54 65 6d 70 50 61 74 68 } //GetTempPath  2
		$a_80_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  2
		$a_80_7 = {47 5a 69 70 53 74 72 65 61 6d } //GZipStream  2
		$a_80_8 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //MemoryStream  2
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2+(#a_80_8  & 1)*2) >=23
 
}