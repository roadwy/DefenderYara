
rule Trojan_BAT_Clipbanker_NBA_MTB{
	meta:
		description = "Trojan:BAT/Clipbanker.NBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 02 7b 39 00 00 04 1e 62 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a d2 60 7d ?? ?? ?? 04 06 17 58 0a 06 1b 3f ?? ?? ?? ff } //5
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_01_2 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 73 00 63 00 20 00 4d 00 49 00 4e 00 55 00 54 00 45 00 20 00 2f 00 6d 00 6f 00 20 00 33 00 20 00 2f 00 74 00 6e 00 } //1 /create /sc MINUTE /mo 3 /tn
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}