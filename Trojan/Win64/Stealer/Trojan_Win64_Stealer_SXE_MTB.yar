
rule Trojan_Win64_Stealer_SXE_MTB{
	meta:
		description = "Trojan:Win64/Stealer.SXE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 "
		
	strings :
		$a_01_0 = {2f 78 6f 70 62 69 78 63 2f 64 61 74 61 2e 70 68 70 } //3 /xopbixc/data.php
		$a_80_1 = {5c 53 6f 66 74 77 61 72 65 5f 49 6e 66 6f 2e 74 78 74 } //\Software_Info.txt  3
		$a_01_2 = {5c 56 69 76 61 6c 64 69 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 4c 6f 67 69 6e 20 44 61 74 61 } //2 \Vivaldi\User Data\Default\Login Data
		$a_01_3 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 45 64 67 65 5c 55 73 65 72 20 44 61 74 61 5c 44 65 66 61 75 6c 74 5c 48 69 73 74 6f 72 79 } //2 \Microsoft\Edge\User Data\Default\History
		$a_80_4 = {5c 45 78 6f 64 75 73 5c 65 78 6f 64 75 73 2e 77 61 6c 6c 65 74 } //\Exodus\exodus.wallet  2
		$a_80_5 = {43 68 72 6f 6d 65 5f 43 6f 69 6e 57 61 6c 6c 65 74 } //Chrome_CoinWallet  2
		$a_80_6 = {53 63 72 65 65 6e 73 68 6f 74 2e 6a 70 67 } //Screenshot.jpg  1
		$a_80_7 = {5c 54 65 6c 65 67 72 61 6d 20 44 65 73 6b 74 6f 70 5c 74 64 61 74 61 } //\Telegram Desktop\tdata  1
		$a_80_8 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 2e 65 78 65 } //ProcessHacker.exe  1
	condition:
		((#a_01_0  & 1)*3+(#a_80_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=17
 
}