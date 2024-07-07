
rule Trojan_Win32_Guloader_SMKT_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SMKT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0f 00 00 "
		
	strings :
		$a_81_0 = {5c 55 6e 64 65 72 6d 61 61 6c 65 72 65 6e 73 34 35 5c 73 6f 62 72 69 71 75 65 74 73 } //1 \Undermaalerens45\sobriquets
		$a_81_1 = {5c 74 6f 75 73 65 73 5c 6d 61 6e 75 63 6f 64 65 5c 73 61 62 75 72 72 61 74 65 5c 76 69 62 72 61 74 69 6f 6e 65 72 2e 69 6e 69 } //1 \touses\manucode\saburrate\vibrationer.ini
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 55 6e 69 6e 73 74 61 6c 6c 5c 66 72 73 74 65 69 6e 73 74 61 6e 73 65 72 5c 62 6c 6f 6d 6b 61 61 6c 73 73 76 61 6d 70 65 73 5c 70 68 79 73 69 6f 67 6e 6f 6d 69 63 61 6c 6c 79 5c 74 6f 76 65 } //1 Software\Microsoft\Windows\CurrentVersion\Uninstall\frsteinstanser\blomkaalssvampes\physiognomically\tove
		$a_81_3 = {53 65 6e 73 69 62 69 6c 69 73 65 72 69 6e 67 65 72 6e 65 73 } //1 Sensibiliseringernes
		$a_81_4 = {61 61 72 73 75 6e 67 65 6e } //1 aarsungen
		$a_81_5 = {5c 4f 6c 64 73 74 65 72 73 5c 63 68 69 6e 6e 69 65 73 74 5c 75 74 65 72 6f 70 6c 61 63 65 6e 74 61 6c 2e 73 6b 6e } //1 \Oldsters\chinniest\uteroplacental.skn
		$a_81_6 = {48 75 73 74 65 6c 65 66 6f 6e 2e 43 6f 75 } //1 Hustelefon.Cou
		$a_81_7 = {47 72 65 65 6e 5f 4c 65 61 76 65 73 5f 31 38 2e 62 6d 70 } //1 Green_Leaves_18.bmp
		$a_81_8 = {5c 50 61 6c 61 65 6f 61 6e 74 68 72 6f 70 6f 6c 6f 67 79 } //1 \Palaeoanthropology
		$a_81_9 = {5c 42 61 63 6b 75 70 6d 6f 64 75 6c 65 72 } //1 \Backupmoduler
		$a_81_10 = {5c 4e 79 62 72 75 64 73 5c 64 61 67 63 65 6e 74 72 65 72 2e 75 6e 61 } //1 \Nybruds\dagcentrer.una
		$a_81_11 = {49 73 63 72 65 6d 65 72 6e 65 35 39 } //1 Iscremerne59
		$a_81_12 = {5c 49 62 6c 61 6e 64 65 6e 64 65 5c 44 72 61 67 6f 6e 65 72 6e 65 73 2e 4d 69 78 } //1 \Iblandende\Dragonernes.Mix
		$a_81_13 = {5c 63 6f 61 78 69 61 6c 5c 6b 61 72 74 61 67 69 73 6b 2e 64 6c 6c } //1 \coaxial\kartagisk.dll
		$a_81_14 = {53 6f 66 74 77 61 72 65 5c 63 69 72 72 69 66 6f 72 6d 5c 6c 6f 6f 66 61 68 5c 73 63 6f 70 75 6c 69 70 65 64 5c } //1 Software\cirriform\loofah\scopuliped\
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1) >=10
 
}