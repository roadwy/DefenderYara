
rule Trojan_Win32_GuLoader_AYC_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 42 00 49 00 52 00 44 00 57 00 45 00 45 00 44 00 5c 00 41 00 66 00 73 00 76 00 72 00 67 00 65 00 6c 00 73 00 65 00 72 00 } //1 Software\BIRDWEED\Afsvrgelser
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 53 00 75 00 6f 00 6d 00 69 00 73 00 5c 00 73 00 6d 00 72 00 65 00 67 00 72 00 61 00 76 00 65 00 6e 00 73 00 } //1 Software\Suomis\smregravens
		$a_01_2 = {41 00 6d 00 62 00 61 00 73 00 73 00 61 00 64 00 72 00 65 00 72 00 6e 00 65 00 35 00 39 00 2e 00 69 00 6e 00 69 00 } //1 Ambassadrerne59.ini
		$a_01_3 = {55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 5c 00 42 00 61 00 61 00 6e 00 64 00 73 00 6b 00 69 00 66 00 74 00 65 00 72 00 6e 00 65 00 31 00 32 00 35 00 2e 00 6c 00 6e 00 6b 00 } //1 USERPROFILE\Baandskifterne125.lnk
		$a_01_4 = {44 00 69 00 73 00 67 00 72 00 61 00 63 00 65 00 64 00 31 00 36 00 36 00 2e 00 64 00 6c 00 6c 00 } //1 Disgraced166.dll
		$a_01_5 = {46 00 6f 00 72 00 74 00 72 00 6e 00 67 00 6e 00 69 00 6e 00 67 00 73 00 6d 00 65 00 6b 00 61 00 6e 00 69 00 73 00 6d 00 65 00 31 00 32 00 2e 00 65 00 78 00 65 00 } //1 Fortrngningsmekanisme12.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_GuLoader_AYC_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.AYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 00 6e 00 75 00 65 00 64 00 65 00 73 00 39 00 5c 00 41 00 4c 00 4c 00 4f 00 50 00 41 00 54 00 52 00 49 00 43 00 41 00 4c 00 4c 00 59 00 5c 00 42 00 65 00 6e 00 6d 00 65 00 6c 00 73 00 73 00 74 00 6f 00 70 00 5c 00 50 00 75 00 6c 00 73 00 61 00 61 00 72 00 65 00 72 00 31 00 2e 00 64 00 69 00 73 00 } //1 Snuedes9\ALLOPATRICALLY\Benmelsstop\Pulsaarer1.dis
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 55 00 6e 00 6f 00 70 00 65 00 6e 00 65 00 64 00 5c 00 47 00 47 00 45 00 53 00 41 00 4c 00 41 00 54 00 45 00 52 00 4e 00 45 00 53 00 5c 00 55 00 74 00 69 00 6c 00 66 00 72 00 65 00 64 00 73 00 68 00 65 00 64 00 73 00 5c 00 53 00 70 00 72 00 67 00 73 00 6d 00 61 00 61 00 6c 00 73 00 74 00 65 00 67 00 6e 00 } //1 Software\Unopened\GGESALATERNES\Utilfredsheds\Sprgsmaalstegn
		$a_01_2 = {53 00 65 00 64 00 69 00 6d 00 65 00 6e 00 74 00 6f 00 6c 00 6f 00 67 00 79 00 5c 00 6d 00 65 00 73 00 65 00 6d 00 62 00 72 00 79 00 6f 00 6e 00 69 00 63 00 5c 00 50 00 61 00 72 00 61 00 62 00 72 00 61 00 6e 00 63 00 68 00 69 00 61 00 74 00 65 00 } //1 Sedimentology\mesembryonic\Parabranchiate
		$a_01_3 = {48 00 75 00 6c 00 6b 00 69 00 6e 00 64 00 65 00 64 00 65 00 73 00 5c 00 65 00 6e 00 74 00 6f 00 6d 00 6f 00 6c 00 6f 00 67 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 68 00 61 00 64 00 65 00 2e 00 6c 00 6e 00 6b 00 } //1 Hulkindedes\entomolog\Windowshade.lnk
		$a_01_4 = {54 00 69 00 6c 00 74 00 75 00 73 00 6b 00 6e 00 69 00 6e 00 67 00 65 00 72 00 35 00 36 00 2e 00 55 00 6e 00 62 00 } //1 Tiltuskninger56.Unb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}