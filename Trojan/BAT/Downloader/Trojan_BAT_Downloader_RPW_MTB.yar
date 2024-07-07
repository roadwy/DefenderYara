
rule Trojan_BAT_Downloader_RPW_MTB{
	meta:
		description = "Trojan:BAT/Downloader.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 00 72 00 69 00 73 00 6e 00 6f 00 76 00 2e 00 70 00 74 00 } //1 prisnov.pt
		$a_01_1 = {55 00 77 00 42 00 30 00 41 00 47 00 45 00 41 00 63 00 67 00 42 00 30 00 41 00 43 00 30 00 41 00 55 00 77 00 42 00 73 00 41 00 47 00 55 00 41 00 5a 00 51 00 42 00 77 00 41 00 43 00 41 00 41 00 4c 00 51 00 42 00 7a 00 41 00 43 00 41 00 41 00 4d 00 51 00 41 00 } //1 UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBzACAAMQA
		$a_01_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_01_3 = {44 00 78 00 6f 00 77 00 6e 00 78 00 6c 00 6f 00 78 00 61 00 64 00 44 00 78 00 61 00 74 00 78 00 78 00 61 00 78 00 } //1 DxownxloxadDxatxxax
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}