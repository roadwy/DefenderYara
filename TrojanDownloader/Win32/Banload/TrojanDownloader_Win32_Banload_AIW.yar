
rule TrojanDownloader_Win32_Banload_AIW{
	meta:
		description = "TrojanDownloader:Win32/Banload.AIW,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {65 77 6f 47 63 4f 6b 38 64 65 73 51 65 78 41 4d 64 38 73 47 5a 39 32 50 59 77 45 65 62 66 36 52 61 38 59 43 65 78 6f 41 5a 4f 73 51 61 4f 6b 66 63 65 73 43 62 66 32 48 } //2 ewoGcOk8desQexAMd8sGZ92PYwEebf6Ra8YCexoAZOsQaOkfcesCbf2H
		$a_01_1 = {68 39 32 50 59 75 59 55 5a 50 67 5a 69 66 51 53 5a 50 32 43 61 39 63 42 65 77 59 4d 61 50 6b 47 59 38 6f 5a 6c 38 67 44 5a 50 67 48 59 77 63 51 5a 4f 6f 4d 61 39 36 5a 6a } //2 h92PYuYUZPgZifQSZP2Ca9cBewYMaPkGY8oZl8gDZPgHYwcQZOoMa96Zj
		$a_01_2 = {6c 65 67 42 61 42 6f 47 61 50 63 4d 63 41 67 6a 69 2f } //2 legBaBoGaPcMcAgji/
		$a_01_3 = {67 67 6f 77 68 51 2b 6a 69 42 63 73 69 78 68 } //1 ggowhQ+jiBcsixh
		$a_01_4 = {6c 67 2b 6c 6b 78 77 68 6c 6c } //1 lg+lkxwhll
		$a_01_5 = {65 76 6f 42 63 50 41 47 5a 54 36 51 58 76 68 } //1 evoBcPAGZT6QXvh
		$a_01_6 = {64 38 6b 50 61 66 32 44 } //1 d8kPaf2D
		$a_01_7 = {5a 75 73 51 63 4f 70 48 62 4f 70 } //1 ZusQcOpHbOp
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}