
rule Trojan_BAT_Agensla_GD_MTB{
	meta:
		description = "Trojan:BAT/Agensla.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 6d 79 6c 69 76 65 72 70 6f 6f 6c 6e 65 77 73 2e 63 66 2f 6c 69 76 65 72 70 6f 6f 6c 2d 66 63 2d 6e 65 77 73 2f 66 65 61 74 75 72 65 73 2f } //http://myliverpoolnews.cf/liverpool-fc-news/features/  1
		$a_80_1 = {57 65 62 43 6c 69 65 6e 74 } //WebClient  1
		$a_80_2 = {55 73 65 72 41 67 65 6e 74 3a } //UserAgent:  1
		$a_80_3 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}