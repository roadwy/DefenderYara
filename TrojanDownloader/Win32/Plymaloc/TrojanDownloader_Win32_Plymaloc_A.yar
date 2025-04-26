
rule TrojanDownloader_Win32_Plymaloc_A{
	meta:
		description = "TrojanDownloader:Win32/Plymaloc.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2d 00 65 00 6e 00 63 00 20 00 55 00 77 00 42 00 30 00 41 00 47 00 45 00 41 00 63 00 67 00 42 00 30 00 41 00 43 00 30 00 41 00 55 00 77 00 42 00 73 00 41 00 47 00 55 00 41 00 5a 00 51 00 42 00 77 00 41 00 43 00 41 00 41 00 4c 00 51 00 42 00 7a 00 41 00 43 00 41 00 41 00 4d 00 51 00 41 00 77 00 } //1 -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQAw
		$a_01_1 = {2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 } //1 //cdn.discordapp.com/attachments/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}