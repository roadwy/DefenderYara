
rule TrojanDownloader_BAT_Shmandaler_A{
	meta:
		description = "TrojanDownloader:BAT/Shmandaler.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 00 4d 00 48 00 61 00 6e 00 64 00 6c 00 65 00 72 00 } //1 /MHandler
		$a_01_1 = {4d 41 67 65 6e 74 00 41 73 73 65 6d 62 6c 79 54 } //1 䅍敧瑮䄀獳浥汢呹
		$a_01_2 = {21 4d 00 41 00 67 00 65 00 6e 00 74 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 } //1 䴡䄀最攀渀琀⸀刀攀猀漀甀爀挀攀猀
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}