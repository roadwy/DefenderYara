
rule TrojanDownloader_Win32_Contaskitar_A{
	meta:
		description = "TrojanDownloader:Win32/Contaskitar.A,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0d 00 00 "
		
	strings :
		$a_03_0 = {2e 73 6b 69 70 70 65 64 69 61 2e 6e 65 74 2f [0-04] 30 32 31 34 64 2f 73 74 61 72 74 32 6d 65 2e 65 78 65 } //8
		$a_01_1 = {67 00 6f 00 6f 00 2e 00 67 00 6c 00 2f 00 7a 00 33 00 77 00 6b 00 6d 00 49 00 } //2 goo.gl/z3wkmI
		$a_01_2 = {67 00 6f 00 6f 00 2e 00 67 00 6c 00 2f 00 48 00 7a 00 6a 00 4a 00 6b 00 52 00 } //2 goo.gl/HzjJkR
		$a_01_3 = {67 00 6f 00 6f 00 2e 00 67 00 6c 00 2f 00 59 00 33 00 75 00 64 00 51 00 36 00 } //2 goo.gl/Y3udQ6
		$a_01_4 = {67 00 6f 00 6f 00 2e 00 67 00 6c 00 2f 00 4e 00 4d 00 51 00 76 00 41 00 } //2 goo.gl/NMQvA
		$a_01_5 = {67 00 6f 00 6f 00 2e 00 67 00 6c 00 2f 00 57 00 51 00 6f 00 46 00 44 00 } //2 goo.gl/WQoFD
		$a_01_6 = {55 52 4c 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6e 74 61 70 72 69 6d 65 2e 63 6f 6d 2f 3f 64 65 73 6b 74 6f 70 } //1 URL=http://www.contaprime.com/?desktop
		$a_01_7 = {43 4f 4e 54 41 50 52 49 4d 45 20 44 4f 57 4e 4c 4f 41 44 53 2e 75 72 6c } //1 CONTAPRIME DOWNLOADS.url
		$a_03_8 = {77 77 77 2e 73 6b 69 70 70 65 64 69 61 2e 6e 65 74 2f 31 ?? 30 32 31 34 64 2f 31 ?? 30 32 31 34 5f [0-04] 2e 65 78 65 } //1
		$a_01_9 = {2f 50 41 52 54 4e 45 52 3d 70 63 64 65 61 6c 70 6c 79 70 6d 20 2f 43 48 41 4e 4e 45 4c 3d 70 63 64 65 61 6c 70 6c 79 70 6d } //1 /PARTNER=pcdealplypm /CHANNEL=pcdealplypm
		$a_01_10 = {2d 61 66 66 69 6c 69 64 3d 31 32 37 34 35 37 } //1 -affilid=127457
		$a_01_11 = {2d 61 66 66 69 6c 69 64 3d 31 32 38 33 39 32 } //1 -affilid=128392
		$a_01_12 = {2f 63 69 64 3d 31 31 37 20 2f 68 61 73 68 3d 66 6f 75 75 66 36 } //1 /cid=117 /hash=fouuf6
	condition:
		((#a_03_0  & 1)*8+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=17
 
}