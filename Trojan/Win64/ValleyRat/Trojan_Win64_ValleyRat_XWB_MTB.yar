
rule Trojan_Win64_ValleyRat_XWB_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.XWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 76 65 6e 77 69 6e 2e 6c 6f 63 6b } //2 C:\Users\Public\venwin.lock
		$a_81_1 = {55 53 44 54 20 68 69 6a 61 63 6b 20 74 68 72 65 61 64 } //2 USDT hijack thread
		$a_81_2 = {5c 76 65 6e 53 75 63 63 65 73 73 2e 69 6e 69 } //1 \venSuccess.ini
		$a_81_3 = {25 50 72 6f 67 72 61 6d 44 61 74 61 25 5c 56 65 6e 6c 6e 6b } //1 %ProgramData%\Venlnk
		$a_81_4 = {42 54 43 20 74 61 72 67 65 74 20 61 64 64 72 65 73 73 } //1 BTC target address
		$a_81_5 = {45 54 48 20 74 61 72 67 65 74 20 61 64 64 72 65 73 73 } //1 ETH target address
		$a_81_6 = {45 6e 61 62 6c 65 4f 66 66 6c 69 6e 65 4b 65 79 62 6f 61 72 64 } //2 EnableOfflineKeyboard
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*2) >=10
 
}