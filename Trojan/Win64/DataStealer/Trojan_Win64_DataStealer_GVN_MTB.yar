
rule Trojan_Win64_DataStealer_GVN_MTB{
	meta:
		description = "Trojan:Win64/DataStealer.GVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 12 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_1 = {2f 62 6f 74 } //1 /bot
		$a_01_2 = {2f 73 65 6e 64 44 6f 63 75 6d 65 6e 74 } //1 /sendDocument
		$a_01_3 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //1 \Google\Chrome\User Data\Default\Login Data
		$a_01_4 = {5c 63 68 72 6f 6d 65 5f 64 61 74 61 2e 74 6d 70 } //1 \chrome_data.tmp
		$a_01_5 = {5c 42 69 74 63 6f 69 6e 5c 77 61 6c 6c 65 74 2e 64 61 74 } //1 \Bitcoin\wallet.dat
		$a_01_6 = {5c 47 6f 6f 67 6c 65 5c 43 68 72 6f 6d 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 63 61 6c 20 45 78 74 65 6e 73 69 6f 6e 20 53 65 74 74 69 6e 67 73 5c 6e 6b 62 69 68 66 62 65 6f 67 61 65 61 6f 65 68 6c 65 66 6e 6b 6f 64 62 65 66 67 70 67 6b 6e 6e } //1 \Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn
		$a_01_7 = {76 6d 74 6f 6f 6c 73 64 2e 65 78 65 } //1 vmtoolsd.exe
		$a_01_8 = {76 6d 77 61 72 65 74 72 61 79 2e 65 78 65 } //1 vmwaretray.exe
		$a_01_9 = {76 62 6f 78 74 72 61 79 2e 65 78 65 } //1 vboxtray.exe
		$a_01_10 = {78 65 6e 73 65 72 76 69 63 65 2e 65 78 65 } //1 xenservice.exe
		$a_01_11 = {77 69 72 65 73 68 61 72 6b 2e 65 78 65 } //1 wireshark.exe
		$a_01_12 = {70 72 6f 63 6d 6f 6e 2e 65 78 65 } //1 procmon.exe
		$a_01_13 = {70 72 6f 63 65 73 73 68 61 63 6b 65 72 2e 65 78 65 } //1 processhacker.exe
		$a_01_14 = {78 36 34 64 62 67 2e 65 78 65 } //1 x64dbg.exe
		$a_01_15 = {67 68 69 64 72 61 2e 65 78 65 } //1 ghidra.exe
		$a_01_16 = {59 4f 55 52 5f 43 48 41 54 5f 49 44 5f 48 45 52 45 } //1 YOUR_CHAT_ID_HERE
		$a_01_17 = {59 4f 55 52 5f 42 4f 54 5f 54 4f 4b 45 4e 5f 48 45 52 45 } //1 YOUR_BOT_TOKEN_HERE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1) >=18
 
}