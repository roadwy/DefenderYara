
rule TrojanDownloader_O97M_StealthFalcon_dha{
	meta:
		description = "TrojanDownloader:O97M/StealthFalcon!dha,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 65 78 20 62 79 70 61 73 73 20 2d 6e 6f 70 20 2d 77 20 68 69 64 64 65 6e 20 2d 6e 6f 6e 69 20 2d 65 20 64 41 42 79 41 48 6b 41 44 51 41 4b 41 48 73 41 44 51 41 4b 41 43 41 41 49 41 41 67 41 43 41 41 4a 41 42 77 41 47 } //1 CreateObject("WScript.Shell").Run "powershell -ex bypass -nop -w hidden -noni -e dAByAHkADQAKAHsADQAKACAAIAAgACAAJABwAG
	condition:
		((#a_01_0  & 1)*1) >=1
 
}