
rule Trojan_BAT_Tiny_BEY_MTB{
	meta:
		description = "Trojan:BAT/Tiny.BEY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 43 79 62 65 72 5f 43 72 79 70 74 65 72 } //1 AppData\Roaming\Cyber_Crypter
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 38 37 37 36 38 39 35 38 32 33 39 35 37 31 39 37 32 34 2f 38 37 37 36 38 39 36 31 30 32 38 37 38 36 31 38 34 30 2f 77 69 6e 6f 6d 6f 65 72 61 2e 64 6c 6c } //1 https://cdn.discordapp.com/attachments/877689582395719724/877689610287861840/winomoera.dll
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}