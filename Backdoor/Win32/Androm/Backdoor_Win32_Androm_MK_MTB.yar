
rule Backdoor_Win32_Androm_MK_MTB{
	meta:
		description = "Backdoor:Win32/Androm.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {4a 75 6d 70 49 44 28 22 22 2c 22 25 73 22 29 } //1 JumpID("","%s")
		$a_81_1 = {53 79 73 74 65 6d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4b 65 79 62 6f 61 72 64 20 4c 61 79 6f 75 74 73 5c 25 2e 38 78 } //1 System\CurrentControlSet\Control\Keyboard Layouts\%.8x
		$a_81_2 = {41 6c 6c 6f 77 43 68 61 6e 67 65 } //1 AllowChange
		$a_81_3 = {53 61 76 65 43 6c 69 70 62 6f 61 72 64 } //1 SaveClipboard
		$a_81_4 = {68 74 74 70 3a 2f 2f 73 74 61 73 32 35 38 2e 6e 61 72 6f 64 2e 72 75 } //1 http://stas258.narod.ru
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}