
rule Trojan_BAT_ClipBanker_GD_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {43 6c 69 70 62 6f 61 72 64 } //Clipboard  1
		$a_80_1 = {52 65 67 65 78 } //Regex  1
		$a_80_2 = {43 6c 69 70 70 65 72 } //Clipper  1
		$a_80_3 = {7a 63 61 73 68 } //zcash  1
		$a_80_4 = {62 69 74 63 6f 69 6e 63 61 73 68 } //bitcoincash  1
		$a_80_5 = {28 62 63 31 7c 5b 31 33 5d 29 5b 61 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 36 2c 33 35 7d } //(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,35}  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule Trojan_BAT_ClipBanker_GD_MTB_2{
	meta:
		description = "Trojan:BAT/ClipBanker.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //SOFTWARE\Microsoft\Windows\CurrentVersion\Run  1
		$a_80_1 = {28 62 63 31 7c 5b 31 33 5d 29 5b 61 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 32 36 2c 33 35 7d } //(bc1|[13])[a-zA-HJ-NP-Z0-9]{26,35}  1
		$a_80_2 = {52 65 67 65 78 } //Regex  1
		$a_80_3 = {43 6c 69 70 70 65 72 } //Clipper  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}