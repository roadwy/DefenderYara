
rule TrojanDownloader_Win32_Karagany_E{
	meta:
		description = "TrojanDownloader:Win32/Karagany.E,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 14 d2 8d 84 50 81 5c fd ff 8a 14 0e 25 ff ff 0f 00 32 d0 } //1
		$a_01_1 = {8d 04 40 8d 4c 41 45 8a 04 16 81 e1 ff ff 07 00 32 c1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}