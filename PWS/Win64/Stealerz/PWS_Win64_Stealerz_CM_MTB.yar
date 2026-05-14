
rule PWS_Win64_Stealerz_CM_MTB{
	meta:
		description = "PWS:Win64/Stealerz.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_01_0 = {73 61 6e 64 62 6f 78 20 63 68 65 63 6b } //2 sandbox check
		$a_01_1 = {44 61 74 61 20 43 6f 6c 6c 65 63 74 69 6f 6e } //2 Data Collection
		$a_01_2 = {54 65 6c 65 67 72 61 6d 3a } //2 Telegram:
		$a_01_3 = {42 72 6f 77 73 65 72 73 3a } //2 Browsers:
		$a_01_4 = {57 61 6c 6c 65 74 73 3a } //2 Wallets:
		$a_01_5 = {44 69 73 63 6f 72 64 3a } //2 Discord:
		$a_01_6 = {43 6c 69 70 62 6f 61 72 64 3a } //2 Clipboard:
		$a_01_7 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 5f 00 69 00 6e 00 66 00 6f 00 2e 00 74 00 78 00 74 00 } //2 \system_info.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2) >=16
 
}