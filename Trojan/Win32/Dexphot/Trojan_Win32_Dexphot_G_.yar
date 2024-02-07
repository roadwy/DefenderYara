
rule Trojan_Win32_Dexphot_G_{
	meta:
		description = "Trojan:Win32/Dexphot.G!!Dexphot.G,SIGNATURE_TYPE_ARHSTR_EXT,0d 00 0d 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {e9 26 00 00 00 61 67 74 30 34 30 31 2e 64 6c 6c 00 43 72 65 61 74 65 4d 75 74 65 78 41 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 60 68 } //03 00 
		$a_01_1 = {58 4d 52 69 67 } //03 00  XMRig
		$a_01_2 = {4a 43 20 45 78 70 65 72 74 20 43 72 79 70 74 6f 6e 6f 74 65 20 43 50 55 20 4d 69 6e 65 72 } //00 00  JC Expert Cryptonote CPU Miner
	condition:
		any of ($a_*)
 
}