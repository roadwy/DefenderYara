
rule Trojan_BAT_Screenlock_Adv{
	meta:
		description = "Trojan:BAT/Screenlock.Adv,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0b 00 00 "
		
	strings :
		$a_80_0 = {41 64 76 61 6e 63 65 64 20 52 61 6e 73 69 5c 41 64 76 61 6e 63 65 64 20 52 61 6e 73 69 5c 6f 62 6a 5c 44 65 62 75 67 5c 41 64 76 61 6e 63 65 64 20 52 61 6e 73 69 2e 70 64 62 } //Advanced Ransi\Advanced Ransi\obj\Debug\Advanced Ransi.pdb  8
		$a_80_1 = {59 6f 75 72 20 43 6f 6d 70 75 74 65 72 20 47 6f 74 20 53 6e 69 70 65 64 20 62 79 20 41 63 72 6f 57 61 72 65 20 43 72 79 70 74 6f 6c 6f 63 6b 65 72 21 } //Your Computer Got Sniped by AcroWare Cryptolocker!  8
		$a_80_2 = {41 64 76 61 6e 63 65 64 5f 52 61 6e 73 69 2e } //Advanced_Ransi.  8
		$a_80_3 = {41 64 76 61 6e 63 65 64 20 52 61 6e 73 69 2e 65 78 65 } //Advanced Ransi.exe  8
		$a_80_4 = {37 32 20 48 6f 75 72 73 20 74 69 6c 6c 20 79 6f 75 72 20 64 61 74 61 20 77 69 6c 6c 20 62 65 20 6c 6f 73 74 } //72 Hours till your data will be lost  4
		$a_80_5 = {41 6c 72 65 61 64 79 20 68 61 76 65 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 6b 65 79 } //Already have the decryption key  4
		$a_80_6 = {59 4f 55 52 20 43 4f 4d 50 55 54 45 52 20 47 4f 54 20 4c 4f 43 4b 45 44 } //YOUR COMPUTER GOT LOCKED  4
		$a_80_7 = {44 65 63 72 79 70 74 21 } //Decrypt!  1
		$a_80_8 = {68 74 74 70 73 3a 2f 2f 62 69 74 70 61 79 2e 63 6f 6d 2f 70 61 79 2d 77 69 74 68 2d 62 69 74 63 6f 69 6e } //https://bitpay.com/pay-with-bitcoin  1
		$a_80_9 = {57 72 6f 6e 67 20 43 6f 64 65 21 } //Wrong Code!  1
		$a_80_10 = {48 6f 75 72 73 20 4c 65 66 74 } //Hours Left  1
	condition:
		((#a_80_0  & 1)*8+(#a_80_1  & 1)*8+(#a_80_2  & 1)*8+(#a_80_3  & 1)*8+(#a_80_4  & 1)*4+(#a_80_5  & 1)*4+(#a_80_6  & 1)*4+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1) >=14
 
}