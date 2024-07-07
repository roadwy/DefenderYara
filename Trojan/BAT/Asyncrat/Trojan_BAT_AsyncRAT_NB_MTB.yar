
rule Trojan_BAT_AsyncRAT_NB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {41 73 79 6e 63 52 41 54 20 7c 20 44 69 73 62 61 6c 65 20 44 65 66 65 6e 64 65 72 } //AsyncRAT | Disbale Defender  1
		$a_80_1 = {4d 69 6e 65 72 20 58 4d 52 } //Miner XMR  1
		$a_80_2 = {52 65 63 6f 76 65 72 79 20 50 61 73 73 77 6f 72 64 } //Recovery Password  1
		$a_80_3 = {4b 65 79 6c 6f 67 67 65 72 } //Keylogger  1
		$a_80_4 = {50 6c 75 67 69 6e 73 5c 57 61 6c 6c 65 74 73 2e 64 6c 6c } //Plugins\Wallets.dll  1
		$a_80_5 = {43 6d 64 20 2f 20 50 6f 77 65 72 73 68 65 6c 6c } //Cmd / Powershell  1
		$a_80_6 = {74 78 74 57 61 6c 6c 65 74 } //txtWallet  1
		$a_80_7 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 4f 46 54 57 41 52 45 5c 41 73 79 6e 63 52 41 54 } //HKEY_CURRENT_USER\SOFTWARE\AsyncRAT  1
		$a_80_8 = {2f 2f 31 32 37 2e 30 2e 30 2e 31 2f 70 61 79 6c 6f 61 64 2e 65 78 65 } ////127.0.0.1/payload.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=9
 
}