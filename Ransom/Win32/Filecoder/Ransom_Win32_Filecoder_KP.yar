
rule Ransom_Win32_Filecoder_KP{
	meta:
		description = "Ransom:Win32/Filecoder.KP,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 61 73 68 43 61 74 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 CashCat.g.resources
		$a_01_1 = {43 61 73 68 43 61 74 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 CashCat.Properties.Resources.resources
		$a_01_2 = {43 61 73 68 43 61 74 52 61 6e 73 6f 6d 77 61 72 65 53 69 6d 75 6c 61 74 6f 72 } //2 CashCatRansomwareSimulator
		$a_01_3 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 47 69 74 48 75 62 5c 43 61 73 68 43 61 74 52 61 6e 73 6f 6d 77 61 72 65 53 69 6d 75 6c 61 74 6f 72 5c 43 61 73 68 43 61 74 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 61 73 68 43 61 74 2e 70 64 62 } //1 \Documents\GitHub\CashCatRansomwareSimulator\CashCat\obj\Debug\CashCat.pdb
		$a_01_4 = {43 61 73 68 43 61 74 2e 65 78 65 } //1 CashCat.exe
		$a_01_5 = {20 54 68 65 20 53 69 6e 67 6c 65 20 63 6f 70 79 20 6f 66 20 74 68 65 20 70 72 69 76 61 74 65 20 6b 65 79 20 77 68 69 63 68 20 61 6c 6c 6f 77 20 79 6f 75 20 74 6f 20 64 65 63 72 79 70 74 20 74 68 65 20 66 69 6c 65 73 20 69 73 20 6f 6e 20 61 20 73 65 63 72 65 74 20 73 65 72 76 65 72 20 6f 6e 20 74 68 65 20 69 6e 74 65 72 6e 65 74 20 64 61 72 6b 20 77 65 62 } //1  The Single copy of the private key which allow you to decrypt the files is on a secret server on the internet dark web
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}