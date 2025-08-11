
rule TrojanDownloader_BAT_SnakeKeyLogger_RK_MTB{
	meta:
		description = "TrojanDownloader:BAT/SnakeKeyLogger.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 36 00 31 00 2e 00 32 00 34 00 38 00 2e 00 32 00 33 00 39 00 2e 00 31 00 31 00 39 00 2f 00 41 00 44 00 4f 00 4c 00 46 00 2f 00 50 00 65 00 6e 00 77 00 63 00 62 00 2e 00 64 00 61 00 74 00 } //1 http://161.248.239.119/ADOLF/Penwcb.dat
		$a_01_1 = {4c 00 63 00 64 00 71 00 76 00 2e 00 65 00 78 00 65 00 } //1 Lcdqv.exe
		$a_01_2 = {79 00 59 00 42 00 55 00 41 00 33 00 4c 00 73 00 50 00 74 00 4c 00 66 00 78 00 39 00 55 00 64 00 52 00 37 00 2e 00 53 00 47 00 43 00 55 00 38 00 78 00 33 00 52 00 53 00 30 00 48 00 64 00 57 00 33 00 6e 00 74 00 6b 00 48 00 } //1 yYBUA3LsPtLfx9UdR7.SGCU8x3RS0HdW3ntkH
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}