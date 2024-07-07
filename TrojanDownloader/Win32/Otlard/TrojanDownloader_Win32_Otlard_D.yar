
rule TrojanDownloader_Win32_Otlard_D{
	meta:
		description = "TrojanDownloader:Win32/Otlard.D,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3f 67 75 69 64 3d 5b 62 6f 74 2d 67 75 69 64 5d 26 70 72 6f 78 79 70 6f 72 74 3d 5b 70 72 6f 78 79 70 6f 72 74 5d 26 70 6c 61 74 66 6f 72 6d 3d 5b 62 6f 74 2d 70 6c 61 74 66 6f 6d 5d } //1 ?guid=[bot-guid]&proxyport=[proxyport]&platform=[bot-platfom]
		$a_01_1 = {5c 25 63 28 5b 5e 5c 25 63 5c 25 63 5d 2b 29 5c 25 63 } //1 \%c([^\%c\%c]+)\%c
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}