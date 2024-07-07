
rule TrojanDownloader_Win32_Tenega_FGTR_MTB{
	meta:
		description = "TrojanDownloader:Win32/Tenega.FGTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {30 2e 2e 2c 27 28 2c 26 26 2c 26 26 2c 26 27 2c 27 28 2c 26 27 2a 25 26 28 24 25 28 24 25 2b 25 25 2b 26 26 28 26 } //1 0..,'(,&&,&&,&','(,&'*%&($%($%+%%+&&(&
		$a_01_1 = {30 40 00 5a 10 40 00 00 00 00 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 44 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}