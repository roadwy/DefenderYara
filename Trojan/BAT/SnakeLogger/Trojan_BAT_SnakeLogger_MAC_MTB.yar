
rule Trojan_BAT_SnakeLogger_MAC_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.MAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 5f 31 30 5f 68 69 73 74 6f 72 69 63 61 6c 5f 6d 69 73 74 61 6b 65 73 5f 69 6e 5f 74 68 65 5f 6d 6f 76 69 65 5f 33 30 30 } //1 get__10_historical_mistakes_in_the_movie_300
		$a_01_1 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 set_UseShellExecute
		$a_01_2 = {41 73 73 65 6d 62 6c 79 49 6e 66 6f } //1 AssemblyInfo
		$a_01_3 = {67 65 74 5f 63 6d 64 6c 6f 61 64 } //1 get_cmdload
		$a_01_4 = {63 6d 64 72 65 70 6f 72 74 } //1 cmdreport
		$a_01_5 = {45 6e 61 62 6c 65 66 75 6e 64 74 72 61 6e 73 66 65 72 } //1 Enablefundtransfer
		$a_01_6 = {54 6f 6f 6c 53 74 72 69 70 49 74 65 6d 43 6c 69 63 6b 65 64 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //1 ToolStripItemClickedEventHandler
		$a_01_7 = {4b 65 79 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //1 KeyEventHandler
		$a_01_8 = {53 65 72 76 65 72 43 6f 6d 70 75 74 65 72 } //1 ServerComputer
		$a_01_9 = {74 78 74 62 61 6e 6b 63 6f 64 65 } //1 txtbankcode
		$a_01_10 = {55 00 50 00 44 00 41 00 54 00 45 00 20 00 53 00 41 00 56 00 49 00 4e 00 47 00 53 00 20 00 41 00 4e 00 44 00 20 00 43 00 52 00 45 00 44 00 49 00 54 00 } //1 UPDATE SAVINGS AND CREDIT
		$a_01_11 = {5c 00 6d 00 65 00 74 00 61 00 64 00 61 00 74 00 61 00 2e 00 74 00 78 00 74 00 } //1 \metadata.txt
		$a_01_12 = {5c 00 70 00 64 00 66 00 74 00 6b 00 2e 00 65 00 78 00 65 00 } //1 \pdftk.exe
		$a_01_13 = {5c 00 2e 00 2e 00 5c 00 73 00 74 00 61 00 74 00 65 00 6d 00 65 00 6e 00 74 00 73 00 } //1 \..\statements
		$a_01_14 = {54 00 65 00 78 00 74 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 28 00 2a 00 2e 00 74 00 78 00 74 00 29 00 7c 00 2a 00 2e 00 74 00 78 00 74 00 7c 00 41 00 6c 00 6c 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 28 00 2a 00 2e 00 2a 00 29 00 7c 00 2a 00 2e 00 2a 00 } //1 Text Files (*.txt)|*.txt|All Files (*.*)|*.*
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1) >=15
 
}