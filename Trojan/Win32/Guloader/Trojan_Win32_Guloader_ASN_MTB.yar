
rule Trojan_Win32_Guloader_ASN_MTB{
	meta:
		description = "Trojan:Win32/Guloader.ASN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6d 6f 6e 65 79 63 68 61 6e 67 65 72 5c 73 75 62 6d 69 63 72 6f 67 72 61 6d 5c 54 61 69 6c 6f 72 69 73 61 74 69 6f 6e 31 31 37 } //1 moneychanger\submicrogram\Tailorisation117
		$a_81_1 = {52 65 64 75 6b 74 69 6f 6e 65 72 32 31 31 5c 55 6e 69 6e 73 74 61 6c 6c 5c 76 6f 63 61 6c 69 73 74 5c 52 65 67 69 6f 6e 73 70 6c 61 6e 72 65 74 6e 69 6e 67 73 6c 69 6e 6a 65 } //1 Reduktioner211\Uninstall\vocalist\Regionsplanretningslinje
		$a_81_2 = {61 6c 6b 61 6c 69 5c 55 6e 69 6e 73 74 61 6c 6c 5c 49 63 6f 6e 69 63 61 6c 6c 79 39 35 } //1 alkali\Uninstall\Iconically95
		$a_81_3 = {49 6d 70 65 72 69 61 6c 69 73 65 73 25 5c 73 71 75 69 62 62 2e 74 78 74 } //1 Imperialises%\squibb.txt
		$a_81_4 = {56 72 64 69 73 6b 61 62 65 6e 64 65 33 32 2e 6a 70 67 } //1 Vrdiskabende32.jpg
		$a_81_5 = {64 6f 6b 75 6d 65 6e 74 66 61 6c 73 6b 6e 65 72 5c 68 65 6c 74 61 6c 73 76 61 65 72 64 69 65 72 2e 65 78 65 } //1 dokumentfalskner\heltalsvaerdier.exe
		$a_81_6 = {73 6b 69 65 67 68 5c 65 6d 70 61 74 68 69 73 65 64 2e 69 6e 69 } //1 skiegh\empathised.ini
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}