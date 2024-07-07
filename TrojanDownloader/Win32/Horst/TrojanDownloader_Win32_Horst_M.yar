
rule TrojanDownloader_Win32_Horst_M{
	meta:
		description = "TrojanDownloader:Win32/Horst.M,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 75 70 2e 6d 65 64 62 6f 64 2e 63 6f 6d 2f } //1 http://up.medbod.com/
		$a_01_1 = {25 73 5c 74 25 64 2e 65 78 65 } //1 %s\t%d.exe
		$a_01_2 = {33 36 34 35 46 42 43 44 2d 45 43 44 32 2d 32 33 44 30 2d 42 41 43 34 2d 30 30 44 45 34 35 33 44 45 46 36 42 } //1 3645FBCD-ECD2-23D0-BAC4-00DE453DEF6B
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}