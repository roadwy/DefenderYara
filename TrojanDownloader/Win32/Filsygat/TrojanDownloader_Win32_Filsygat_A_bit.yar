
rule TrojanDownloader_Win32_Filsygat_A_bit{
	meta:
		description = "TrojanDownloader:Win32/Filsygat.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 66 69 6c 65 53 79 73 74 65 6d 22 20 2f 74 72 20 } //01 00  schtasks /create /tn "fileSystem" /tr 
		$a_01_1 = {00 2e 63 6f 6d 00 2e 6e 65 74 00 2e 6f 72 67 00 } //01 00  ⸀潣m渮瑥⸀牯g
		$a_01_2 = {00 2f 63 2e 70 68 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}