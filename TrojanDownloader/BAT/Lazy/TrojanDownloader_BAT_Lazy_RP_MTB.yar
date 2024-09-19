
rule TrojanDownloader_BAT_Lazy_RP_MTB{
	meta:
		description = "TrojanDownloader:BAT/Lazy.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 41 4c 49 45 4e 57 41 52 45 5c 44 6f 77 6e 6c 6f 61 64 73 5c 54 65 6c 65 67 72 61 6d 20 44 65 73 6b 74 6f 70 5c 43 6f 6e 73 6f 6c 65 41 70 70 31 5c 43 6f 6e 73 6f 6c 65 41 70 70 31 5c 6f 62 6a 5c 44 65 62 75 67 5c } //10 C:\Users\ALIENWARE\Downloads\Telegram Desktop\ConsoleApp1\ConsoleApp1\obj\Debug\
		$a_01_1 = {64 00 65 00 6c 00 20 00 64 00 65 00 6c 00 2e 00 62 00 61 00 74 00 } //1 del del.bat
		$a_01_2 = {6c 00 6f 00 61 00 64 00 65 00 72 00 32 00 30 00 } //1 loader20
		$a_01_3 = {55 00 32 00 39 00 6d 00 64 00 48 00 64 00 68 00 63 00 6d 00 56 00 4a 00 62 00 6e 00 4e 00 30 00 59 00 57 00 78 00 73 00 5a 00 58 00 49 00 71 00 } //1 U29mdHdhcmVJbnN0YWxsZXIq
		$a_01_4 = {5f 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 24 00 } //10 _Encrypted$
		$a_01_5 = {53 6f 66 74 77 61 72 65 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //1 SoftwareInstaller.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_01_5  & 1)*1) >=24
 
}