
rule Trojan_Win64_ClipBanker_A_AMTB{
	meta:
		description = "Trojan:Win64/ClipBanker.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {4f 6f 70 73 21 20 59 6f 75 72 20 4d 42 52 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 41 45 53 20 6d 69 6c 69 74 61 72 79 20 61 6c 67 6f 72 69 74 68 6d 2e } //Oops! Your MBR are encrypted with AES military algorithm.  1
		$a_80_1 = {54 6f 20 72 65 73 74 6f 72 65 20 79 6f 75 72 20 4d 42 52 20 62 61 63 6b 2c 20 73 65 6e 64 20 34 30 24 20 69 6e 20 4c 54 43 20 6f 72 20 42 54 43 20 74 6f 20 74 68 65 20 77 61 6c 6c 65 74 73 } //To restore your MBR back, send 40$ in LTC or BTC to the wallets  1
		$a_80_2 = {53 75 70 70 6f 72 74 20 69 6e 20 52 79 7a 65 20 4a 6f 69 6e 65 72 20 53 65 72 76 65 72 2e } //Support in Ryze Joiner Server.  1
		$a_80_3 = {49 66 20 79 6f 75 20 72 65 73 74 61 72 74 20 79 6f 75 72 20 50 43 20 77 69 74 68 6f 75 74 20 73 75 62 6d 69 74 74 69 6e 67 20 61 20 6b 65 79 2c 20 69 74 20 77 69 6c 6c 20 62 65 20 79 6f 75 72 20 6c 61 73 74 20 74 69 6d 65 20 75 73 69 6e 67 20 69 74 2e } //If you restart your PC without submitting a key, it will be your last time using it.  1
		$a_80_4 = {4c 54 43 20 61 64 64 72 65 73 73 20 63 6f 70 69 65 64 21 } //LTC address copied!  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}