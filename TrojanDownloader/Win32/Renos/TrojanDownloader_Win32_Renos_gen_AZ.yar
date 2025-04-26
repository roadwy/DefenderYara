
rule TrojanDownloader_Win32_Renos_gen_AZ{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!AZ,SIGNATURE_TYPE_PEHSTR,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {25 64 2e 25 64 2e 25 6c 73 2e 63 68 72 2e 73 61 6e 74 61 2d 69 6e 62 6f 78 2e 63 6f 6d } //2 %d.%d.%ls.chr.santa-inbox.com
		$a_01_1 = {42 00 6c 00 75 00 65 00 73 00 63 00 72 00 65 00 65 00 6e 00 20 00 53 00 63 00 72 00 65 00 65 00 6e 00 20 00 53 00 61 00 76 00 65 00 72 00 } //1 Bluescreen Screen Saver
		$a_01_2 = {67 6f 66 75 63 6b 79 6f 75 72 73 65 6c 66 2e 63 6f 6d } //1 gofuckyourself.com
		$a_01_3 = {74 69 62 73 79 73 74 65 6d 73 2e } //1 tibsystems.
		$a_01_4 = {25 00 73 00 2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 25 00 64 00 2f 00 25 00 73 00 2f 00 25 00 73 00 2e 00 67 00 69 00 66 00 } //1 %s/images/%d/%s/%s.gif
		$a_01_5 = {2e 00 70 00 68 00 70 00 3f 00 69 00 64 00 3d 00 25 00 } //1 .php?id=%
		$a_01_6 = {61 00 76 00 78 00 70 00 30 00 38 00 2e 00 6e 00 65 00 74 00 } //1 avxp08.net
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}