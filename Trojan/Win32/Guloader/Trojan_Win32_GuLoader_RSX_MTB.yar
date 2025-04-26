
rule Trojan_Win32_GuLoader_RSX_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {23 5c 4b 61 6c 6b 76 72 6b 73 61 72 62 65 6a 64 65 72 65 6e 38 34 5c 63 68 65 67 6f 5c 72 65 76 65 72 65 6e 73 65 6e 73 } //1 #\Kalkvrksarbejderen84\chego\reverensens
		$a_81_1 = {73 75 70 65 72 6e 6f 76 61 73 5c 6d 65 73 61 6c 6c 69 61 6e 63 65 72 73 5c 53 65 6b 73 61 61 72 69 6e 67 65 6e } //1 supernovas\mesalliancers\Seksaaringen
		$a_81_2 = {5c 62 65 74 72 6e 67 74 65 73 5c 68 6f 63 6b 73 68 69 6e 2e 54 6f 65 } //1 \betrngtes\hockshin.Toe
		$a_81_3 = {62 69 6d 61 68 73 20 77 65 65 6e 73 69 65 72 20 73 70 69 6c 64 65 76 61 6e 64 73 6c 65 64 6e 69 6e 67 65 72 6e 65 73 } //1 bimahs weensier spildevandsledningernes
		$a_81_4 = {69 6e 66 6c 75 65 6e 7a 61 65 70 69 64 65 6d 69 65 6e 73 20 64 6f 6b 74 6f 72 65 6e } //1 influenzaepidemiens doktoren
		$a_81_5 = {6e 61 64 76 65 72 67 73 74 2e 65 78 65 } //1 nadvergst.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}