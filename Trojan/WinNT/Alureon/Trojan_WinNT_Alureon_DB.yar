
rule Trojan_WinNT_Alureon_DB{
	meta:
		description = "Trojan:WinNT/Alureon.DB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 70 3c 03 f0 8b 46 50 89 45 ?? 6a 40 68 00 30 00 00 8d 45 ?? 50 53 8d 45 ?? 50 ff 75 08 ff 15 } //1
		$a_03_1 = {8b 0a 03 ce 33 ff eb 0e 0f bf 19 69 ff ?? ?? ?? ?? 03 fb 41 33 db 38 19 75 ee 39 7d 0c 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}