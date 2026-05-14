
rule Trojan_BAT_PswStealer_PAHR_MTB{
	meta:
		description = "Trojan:BAT/PswStealer.PAHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0b 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 5a 69 70 } //1 sendZip
		$a_01_1 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //2 set_UseShellExecute
		$a_01_2 = {3c 74 65 6d 70 4c 6f 67 69 6e 44 61 74 61 50 61 74 68 3e } //1 <tempLoginDataPath>
		$a_01_3 = {3c 54 61 6b 65 53 65 73 73 69 6f 6e 3e } //1 <TakeSession>
		$a_01_4 = {3c 53 61 76 65 54 6f 46 69 6c 65 3e } //1 <SaveToFile>
		$a_01_5 = {3c 63 68 65 63 6b 57 61 6c 6c 65 74 73 3e } //1 <checkWallets>
		$a_01_6 = {3c 70 77 64 73 3e } //1 <pwds>
		$a_01_7 = {3c 63 6f 6f 6b 69 65 73 3e } //2 <cookies>
		$a_01_8 = {3c 6c 6f 61 64 45 6e 63 72 4b 65 79 73 3e } //2 <loadEncrKeys>
		$a_00_9 = {63 00 73 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 20 00 67 00 65 00 74 00 20 00 75 00 75 00 69 00 64 00 } //1 csproduct get uuid
		$a_01_10 = {67 65 74 5f 42 72 6f 77 73 65 72 4e 61 6d 65 } //1 get_BrowserName
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_00_9  & 1)*1+(#a_01_10  & 1)*1) >=14
 
}