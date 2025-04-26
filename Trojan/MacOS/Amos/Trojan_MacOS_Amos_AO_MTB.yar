
rule Trojan_MacOS_Amos_AO_MTB{
	meta:
		description = "Trojan:MacOS/Amos.AO!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 61 6c 6c 65 74 77 61 73 61 62 69 2f 63 6c 69 65 6e 74 2f 57 61 6c 6c 65 74 73 2f } //5 walletwasabi/client/Wallets/
		$a_01_1 = {45 78 6f 64 75 73 2f 65 78 6f 64 75 73 2e 77 61 6c 6c 65 74 2f } //5 Exodus/exodus.wallet/
		$a_01_2 = {61 74 6f 6d 69 63 2f 4c 6f 63 61 6c 20 53 74 76 65 6c 64 62 2f } //1 atomic/Local Stveldb/
		$a_01_3 = {47 75 61 72 64 61 2f 4c 6f 63 61 6c 20 53 74 6f 72 61 67 65 2f 6c 65 76 65 6c 64 62 2f } //1 Guarda/Local Storage/leveldb/
		$a_03_4 = {ff 43 01 d1 fd 7b 04 a9 fd 03 01 91 a0 83 1f f8 a8 83 5f f8 e8 07 00 f9 e0 83 00 91 e0 03 00 f9 61 00 00 f0 21 f8 06 91 6a ?? ?? ?? e1 03 40 f9 e2 07 40 f9 e0 03 02 aa } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=11
 
}