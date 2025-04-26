
rule TrojanDownloader_Win32_Dofoil_gen_C{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 72 6b 00 00 68 00 00 57 6f } //1
		$a_01_1 = {b0 68 aa 8b 45 fc ab b0 c3 aa } //1
		$a_03_2 = {e2 ea eb d4 61 89 c5 8d bb ?? ?? ?? ?? 03 80 78 01 00 00 8b 48 14 0b 48 18 74 28 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}