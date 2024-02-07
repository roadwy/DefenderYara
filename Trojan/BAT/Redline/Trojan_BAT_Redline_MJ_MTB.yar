
rule Trojan_BAT_Redline_MJ_MTB{
	meta:
		description = "Trojan:BAT/Redline.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 73 6f 6c 65 43 61 6e 63 65 6c 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ConsoleCancel.g.resources
		$a_01_1 = {43 6f 6e 73 6f 6c 65 4b 65 79 49 6e 66 6f 2e 43 72 79 70 74 6f 2e 46 6f 72 6d 31 } //01 00  ConsoleKeyInfo.Crypto.Form1
		$a_01_2 = {65 34 61 39 33 33 33 64 2d 31 61 38 39 2d 34 61 62 37 2d 38 36 37 39 2d 34 32 34 32 30 37 61 33 63 32 34 61 } //01 00  e4a9333d-1a89-4ab7-8679-424207a3c24a
		$a_01_3 = {43 6f 6e 73 6f 6c 65 43 61 6e 63 65 6c 2e 65 78 65 } //00 00  ConsoleCancel.exe
	condition:
		any of ($a_*)
 
}