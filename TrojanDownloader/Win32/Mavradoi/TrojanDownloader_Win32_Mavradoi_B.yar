
rule TrojanDownloader_Win32_Mavradoi_B{
	meta:
		description = "TrojanDownloader:Win32/Mavradoi.B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {75 37 36 67 76 66 44 62 75 4b 76 43 74 75 4c 64 75 4b 36 74 74 37 7a 75 78 66 44 6a 74 4b 72 70 76 31 6e 43 71 31 76 73 75 4b 76 6f 76 66 7a 66 75 4c 6e 6a 74 37 39 43 75 4c 76 6f } //4 u76gvfDbuKvCtuLduK6tt7zuxfDjtKrpv1nCq1vsuKvovfzfuLnjt79CuLvo
		$a_01_1 = {75 37 36 67 76 66 44 62 75 4b 76 43 74 77 4c 4a 43 4d 36 5a 42 38 7a 37 78 66 44 50 42 4d 72 56 44 32 } //4 u76gvfDbuKvCtwLJCM6ZB8z7xfDPBMrVD2
		$a_01_2 = {43 71 32 76 59 43 4d 76 55 44 66 7a 4c 43 4e 6e 50 42 38 33 } //2 Cq2vYCMvUDfzLCNnPB83
		$a_01_3 = {2f 6d 32 70 72 2e 6f 72 67 2f 6d 61 74 65 72 69 61 6c 2f 67 61 6c 65 72 69 61 5f 69 6d 61 67 65 6e 73 2f 39 39 2f 61 64 6d 2f 69 6d 61 67 65 73 2f 69 6e 66 66 2e 70 68 70 } //3 /m2pr.org/material/galeria_imagens/99/adm/images/inff.php
		$a_01_4 = {7a 67 76 5a 41 32 72 56 43 64 69 } //2 zgvZA2rVCdi
		$a_01_5 = {75 68 6a 56 7a 32 6a 48 42 75 7a 50 42 67 76 5a 72 67 4c 59 } //2 uhjVz2jHBuzPBgvZrgLY
		$a_01_6 = {75 68 6a 56 7a 68 76 4a 44 65 39 48 42 77 75 } //2 uhjVzhvJDe9HBwu
		$a_01_7 = {72 37 6a 71 74 66 76 68 73 75 33 } //2 r7jqtfvhsu3
		$a_01_8 = {6b 49 4f 51 69 65 31 48 42 67 72 50 44 67 35 47 41 77 39 5a 44 67 66 53 79 77 72 56 69 63 4f 51 6b 47 } //2 kIOQie1HBgrPDg5GAw9ZDgfSywrVicOQkG
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2) >=9
 
}