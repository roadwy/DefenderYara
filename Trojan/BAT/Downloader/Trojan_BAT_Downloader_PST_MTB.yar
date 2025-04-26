
rule Trojan_BAT_Downloader_PST_MTB{
	meta:
		description = "Trojan:BAT/Downloader.PST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 31 30 37 38 37 38 30 36 37 34 38 36 33 39 32 34 35 2f 39 31 30 39 30 32 33 34 36 36 38 31 33 31 35 33 33 38 2f 4f 6e 61 6e 61 5f 48 6f 73 70 69 74 61 6c 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 64 6c 6c } //1 https://cdn.discordapp.com/attachments/910787806748639245/910902346681315338/Onana_Hospital_Management_System.dll
		$a_81_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_81_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_81_3 = {65 78 65 2e 78 65 79 61 70 2f 30 33 35 38 38 39 33 36 35 30 34 37 35 35 35 30 31 39 2f 31 30 37 33 32 39 34 30 33 34 39 32 38 32 34 30 31 39 2f 73 74 6e 65 6d 68 63 61 74 74 61 2f 6d 6f 63 2e 70 70 61 64 72 6f 63 73 69 64 2e 6e 64 63 2f 2f 3a 73 70 74 74 68 } //1 exe.xeyap/035889365047555019/107329403492824019/stnemhcatta/moc.ppadrocsid.ndc//:sptth
		$a_81_4 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_6 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_81_7 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}