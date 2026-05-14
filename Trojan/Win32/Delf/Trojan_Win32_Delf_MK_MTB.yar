
rule Trojan_Win32_Delf_MK_MTB{
	meta:
		description = "Trojan:Win32/Delf.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 06 00 00 "
		
	strings :
		$a_81_0 = {53 70 66 75 77 62 72 66 5c 4e 69 64 72 70 73 70 66 75 5c 58 69 6f 64 70 77 74 5c 44 75 73 72 66 6e 75 56 66 72 74 69 70 6e 5d 52 76 6e } //15 Spfuwbrf\Nidrpspfu\Xiodpwt\DusrfnuVfrtipn]Rvn
		$a_81_1 = {42 6f 74 20 53 74 61 72 74 65 64 21 } //15 Bot Started!
		$a_81_2 = {73 74 61 72 74 20 22 22 20 25 25 66 6c 25 25 } //10 start "" %%fl%%
		$a_81_3 = {64 65 6c 20 2f 71 20 25 25 30 } //10 del /q %%0
		$a_81_4 = {43 61 6e 74 20 4c 6f 61 64 20 64 6c 6c 20 66 72 6f 6d 20 73 65 72 76 65 72 } //5 Cant Load dll from server
		$a_81_5 = {53 74 61 72 74 20 52 65 63 65 69 76 65 20 64 6c 6c 2e 20 53 74 61 74 75 73 } //5 Start Receive dll. Status
	condition:
		((#a_81_0  & 1)*15+(#a_81_1  & 1)*15+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*5+(#a_81_5  & 1)*5) >=60
 
}