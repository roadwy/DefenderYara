
rule Trojan_BAT_Tiny_DA_MTB{
	meta:
		description = "Trojan:BAT/Tiny.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 16 11 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 06 11 04 11 06 6f ?? ?? ?? 0a 13 07 09 11 07 6f ?? ?? ?? 0a 26 00 11 05 17 d6 13 05 11 05 1e 31 d0 } //1
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_2 = {2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f } //1 /cdn.discordapp.com/attachments/
		$a_81_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c } //1 Software\Microsoft\Windows\CurrentVersion\Run\
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}