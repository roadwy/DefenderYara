
rule Backdoor_Linux_CoinThief_B{
	meta:
		description = "Backdoor:Linux/CoinThief.B,SIGNATURE_TYPE_MACHOHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 61 66 61 72 69 45 78 74 65 6e 73 69 6f 6e 4d 6f 6e 69 74 6f 72 00 63 68 72 6f 6d 65 45 78 74 65 6e 73 69 6f 6e 4d 6f 6e 69 74 6f 72 } //2
		$a_01_1 = {66 73 36 33 34 38 39 32 33 6c 6f 63 6b 00 41 67 65 6e 74 } //2
		$a_01_2 = {2f 74 6d 70 2f 5f 61 67 6e 25 6c 75 } //2 /tmp/_agn%lu
		$a_01_3 = {69 73 42 69 74 63 6f 69 6e 51 74 49 6e 73 74 61 6c 6c 65 64 } //2 isBitcoinQtInstalled
		$a_01_4 = {62 69 74 63 6f 69 6e 51 74 50 61 74 63 68 65 64 00 30 66 30 61 66 63 33 38 30 38 38 61 33 65 30 33 38 64 39 39 35 38 63 65 66 37 37 37 33 63 66 39 } //2
		$a_01_5 = {2f 58 63 6f 64 65 2f 44 65 72 69 76 65 64 44 61 74 61 2f 49 6e 6a 65 63 74 6f 72 2d } //2 /Xcode/DerivedData/Injector-
		$a_01_6 = {50 4f 53 54 20 5c 2f 28 5b 5e 20 5d 2a 29 20 48 54 54 50 5c 2f 31 5c 2e 28 5b 30 31 5d 29 2e 2a 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 28 5b 30 2d 39 5d 2b 29 2e 2a 25 40 25 40 } //2 POST \/([^ ]*) HTTP\/1\.([01]).*Content-Length: ([0-9]+).*%@%@
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=12
 
}