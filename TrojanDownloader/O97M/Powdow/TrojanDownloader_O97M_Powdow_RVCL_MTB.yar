
rule TrojanDownloader_O97M_Powdow_RVCL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 2f 63 73 74 61 72 74 2f 6d 69 6e 70 6f 22 63 61 72 32 3d 22 77 65 72 73 68 65 6c 6c 2d 65 78 62 79 22 63 61 72 33 3d 22 70 61 73 73 2d 6e 6f 70 2d 77 68 3b 69 27 65 27 78 28 69 77 22 63 61 72 34 3d 22 72 28 27 68 74 74 70 73 3a 2f 2f } //1 cmd/cstart/minpo"car2="wershell-exby"car3="pass-nop-wh;i'e'x(iw"car4="r('https://
		$a_01_1 = {2f 66 63 38 66 31 39 62 32 66 36 38 65 30 39 62 30 39 66 31 63 36 39 61 66 30 36 36 66 66 64 36 66 65 32 63 64 32 30 63 61 2f 66 69 6c 65 73 2f 62 6c 61 63 6b 2d 73 74 61 72 74 2e 74 78 74 27 29 2d 75 73 65 62 29 3b 73 74 61 72 74 2d 73 6c 65 65 70 } //1 /fc8f19b2f68e09b09f1c69af066ffd6fe2cd20ca/files/black-start.txt')-useb);start-sleep
		$a_01_2 = {73 68 65 6c 6c 69 5f 6e 61 6d 65 65 6e 64 66 75 6e 63 74 69 6f 6e } //1 shelli_nameendfunction
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}