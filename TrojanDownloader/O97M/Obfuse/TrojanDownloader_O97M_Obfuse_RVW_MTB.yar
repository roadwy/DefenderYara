
rule TrojanDownloader_O97M_Obfuse_RVW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 CreateObject("WScript.Shell")
		$a_01_1 = {64 64 7a 64 71 73 64 66 66 28 29 20 26 20 22 5c 22 20 2b 20 72 6d 6c 6b 65 6a 67 6d 6c 6b 64 66 6a 67 72 69 28 32 29 20 2b 20 22 2e 65 78 65 22 } //1 ddzdqsdff() & "\" + rmlkejgmlkdfjgri(2) + ".exe"
		$a_01_2 = {50 78 50 54 6f 78 68 71 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 73 64 71 73 6c 64 6a 6b 66 2c 20 46 61 6c 73 65 } //1 PxPToxhq.Open "GET", sdqsldjkf, False
		$a_01_3 = {73 6c 6b 66 6a 64 66 6a 68 67 6c 6b 6a 64 73 68 7a 65 2e 52 75 6e 20 58 78 58 2c 20 31 2c 20 54 72 75 65 } //1 slkfjdfjhglkjdshze.Run XxX, 1, True
		$a_01_4 = {73 74 72 20 26 20 4d 69 64 28 4c 45 54 54 45 52 53 2c 20 49 6e 74 28 73 74 72 4c 65 6e 20 2a 20 52 6e 64 20 2b 20 31 29 29 } //1 str & Mid(LETTERS, Int(strLen * Rnd + 1))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}