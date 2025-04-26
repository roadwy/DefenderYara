
rule TrojanDownloader_O97M_EncDoc_M_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.M!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 18 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 49 77 52 48 78 4d 2e 65 78 65 } //1 C:\ProgramData\MIwRHxM.exe
		$a_01_1 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6b 67 55 70 66 57 6b 2e 65 78 65 } //1 C:\ProgramData\kgUpfWk.exe
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 56 6a 52 69 55 59 79 2e 65 78 65 } //1 C:\ProgramData\VjRiUYy.exe
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 73 6f 64 78 6f 66 73 2e 64 6c 6c } //1 C:\ProgramData\sodxofs.dll
		$a_01_4 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 74 6f 64 78 6f 66 73 2e 64 6c 6c } //1 C:\ProgramData\todxofs.dll
		$a_01_5 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 42 79 73 4b 49 65 7a 2e 64 6c 6c } //1 C:\ProgramData\BysKIez.dll
		$a_01_6 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 6c 72 6e 79 44 52 6d 2e 64 6c 6c } //1 C:\ProgramData\lrnyDRm.dll
		$a_01_7 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 62 70 58 6f 61 65 45 2e 64 6c 6c } //1 C:\ProgramData\bpXoaeE.dll
		$a_01_8 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4f 77 77 6a 57 78 55 2e 64 6c 6c } //1 C:\ProgramData\OwwjWxU.dll
		$a_01_9 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 7a 69 69 57 49 6a 47 2e 64 6c 6c } //1 C:\ProgramData\ziiWIjG.dll
		$a_01_10 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 67 6f 42 64 77 63 42 2e 64 6c 6c } //1 C:\ProgramData\goBdwcB.dll
		$a_01_11 = {43 3a 5c 6c 55 55 48 74 56 72 5c 45 53 7a 52 44 48 67 5c 62 58 4d 67 57 4e 62 2e 64 6c 6c } //1 C:\lUUHtVr\ESzRDHg\bXMgWNb.dll
		$a_01_12 = {43 3a 5c 77 43 6e 67 6e 52 65 5c 64 74 78 42 72 52 67 5c 48 5a 55 4b 70 78 79 2e 64 6c 6c } //1 C:\wCngnRe\dtxBrRg\HZUKpxy.dll
		$a_01_13 = {43 3a 5c 7a 4b 66 73 66 53 74 5c 51 4f 71 59 70 62 66 5c 51 7a 68 6b 46 68 6c 2e 64 6c 6c } //1 C:\zKfsfSt\QOqYpbf\QzhkFhl.dll
		$a_01_14 = {43 3a 5c 76 65 65 52 45 66 43 5c 4f 63 4b 62 4e 52 72 5c 6c 68 57 71 68 58 6c 2e 64 6c 6c } //1 C:\veeREfC\OcKbNRr\lhWqhXl.dll
		$a_01_15 = {43 3a 5c 67 6d 69 74 77 4d 68 5c 69 73 43 77 61 71 4a 5c 49 47 7a 53 50 6c 49 2e 64 6c 6c } //1 C:\gmitwMh\isCwaqJ\IGzSPlI.dll
		$a_01_16 = {43 3a 5c 52 62 77 4b 78 6a 4c 5c 68 67 49 70 48 73 77 5c 68 53 7a 43 57 79 45 2e 64 6c 6c } //1 C:\RbwKxjL\hgIpHsw\hSzCWyE.dll
		$a_01_17 = {43 3a 5c 68 51 51 44 70 51 6d 5c 7a 4f 75 4d 79 44 63 5c 58 54 48 63 53 4a 58 2e 65 78 65 } //1 C:\hQQDpQm\zOuMyDc\XTHcSJX.exe
		$a_01_18 = {43 3a 5c 70 59 59 4c 78 59 75 5c 49 57 44 56 48 4c 6b 5c 66 62 50 6b 61 52 66 2e 65 78 65 } //1 C:\pYYLxYu\IWDVHLk\fbPkaRf.exe
		$a_01_19 = {55 52 4c 4d 4f 4e } //1 URLMON
		$a_01_20 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_01_21 = {53 68 65 6c 6c 33 32 } //1 Shell32
		$a_01_22 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
		$a_01_23 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //1 rundll32.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_01_22  & 1)*1+(#a_01_23  & 1)*1) >=6
 
}