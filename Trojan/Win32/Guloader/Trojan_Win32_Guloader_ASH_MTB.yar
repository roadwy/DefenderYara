
rule Trojan_Win32_Guloader_ASH_MTB{
	meta:
		description = "Trojan:Win32/Guloader.ASH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 6e 67 68 6f 75 73 65 5c 48 61 62 69 6c 69 6d 65 6e 74 61 74 69 6f 6e 32 32 36 2e 69 6e 69 } //1 longhouse\Habilimentation226.ini
		$a_01_1 = {55 61 67 74 73 6f 6d 6d 65 73 5c 45 66 74 65 72 6d 69 64 64 61 67 73 6d 61 61 6c 74 69 64 65 72 73 5c 73 6d 75 64 73 65 } //1 Uagtsommes\Eftermiddagsmaaltiders\smudse
		$a_01_2 = {73 6a 6c 64 65 6e 68 65 64 65 72 5c 53 79 72 65 62 61 64 65 74 73 2e 74 6f 72 } //1 sjldenheder\Syrebadets.tor
		$a_01_3 = {72 65 73 66 6f 72 6e 72 6d 65 6e 64 65 73 5c 50 72 69 6e 74 65 72 6b 6f 6d 6d 61 6e 64 6f 2e 76 65 6c } //1 resfornrmendes\Printerkommando.vel
		$a_01_4 = {67 74 65 73 6b 61 62 73 73 61 67 65 6e 5c 41 66 6b 72 69 73 74 6e 65 6e 64 65 73 2e 64 6c 6c } //1 gteskabssagen\Afkristnendes.dll
		$a_01_5 = {54 6f 74 61 6c 73 61 6e 65 72 69 6e 67 65 6e 32 34 32 2e 74 78 74 } //1 Totalsaneringen242.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Guloader_ASH_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.ASH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {41 52 4d 4f 55 52 59 20 43 52 41 54 45 20 65 47 50 55 20 50 72 6f 64 75 63 74 2e 65 78 65 } //1 ARMOURY CRATE eGPU Product.exe
		$a_01_1 = {67 6e 6f 6d 65 2d 70 6f 77 65 72 2d 6d 61 6e 61 67 65 72 2d 73 79 6d 62 6f 6c 69 63 2e 73 76 67 } //1 gnome-power-manager-symbolic.svg
		$a_01_2 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 6d 6f 6e 6f 70 6e 65 75 6d 6f 61 } //1 CurrentVersion\Uninstall\monopneumoa
		$a_01_3 = {55 6e 69 6e 73 74 61 6c 6c 5c 42 65 64 6d 61 74 65 73 5c 54 72 6f 70 69 6b 66 72 6f 6e 74 65 6e } //1 Uninstall\Bedmates\Tropikfronten
		$a_01_4 = {44 61 74 69 64 73 66 6f 72 6d 65 6e 73 5c 4f 46 46 45 4e 54 4c 49 47 48 45 44 45 4e 53 2e 69 6e 69 } //1 Datidsformens\OFFENTLIGHEDENS.ini
		$a_01_5 = {48 45 58 33 32 2e 44 4c 4c } //1 HEX32.DLL
		$a_01_6 = {4b 61 74 61 6c 6f 67 62 65 73 74 69 6c 6c 69 6e 67 5c 47 65 6e 74 6c 65 73 74 37 5c 53 74 74 74 65 76 6f 6b 61 6c 65 72 73 2e 6c 6e 6b } //1 Katalogbestilling\Gentlest7\Stttevokalers.lnk
		$a_01_7 = {56 69 6e 64 69 6e 67 65 72 5c 45 76 61 64 74 72 65 6e 65 73 2e 64 6c 6c } //1 Vindinger\Evadtrenes.dll
		$a_01_8 = {61 66 73 74 75 6d 70 6e 69 6e 67 5c 53 70 69 6c 64 65 6f 6c 69 65 2e 64 6c 6c } //1 afstumpning\Spildeolie.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}