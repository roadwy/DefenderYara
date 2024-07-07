
rule TrojanDownloader_Win32_Banload_ACJ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ACJ,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 23 23 6a 23 70 23 67 } //1 .##j#p#g
		$a_01_1 = {23 63 3a 23 5c 23 77 23 69 23 6e 74 23 78 23 33 23 32 23 5c 23 } //1 #c:#\#w#i#nt#x#3#2#\#
		$a_01_2 = {43 75 23 72 72 65 23 6e 74 56 65 72 23 73 69 23 6f 6e 5c 52 75 23 6e } //1 Cu#rre#ntVer#si#on\Ru#n
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}