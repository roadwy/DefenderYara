
rule Ransom_Win32_FileCoder_BAB_MTB{
	meta:
		description = "Ransom:Win32/FileCoder.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {52 61 6e 73 6f 6d 20 4e 6f 74 65 } //1 Ransom Note
		$a_81_1 = {44 65 73 6b 74 6f 70 20 77 61 6c 6c 70 61 70 65 72 20 63 68 61 6e 67 65 64 20 74 6f 20 72 61 6e 73 6f 6d 20 69 6d 61 67 65 } //1 Desktop wallpaper changed to ransom image
		$a_81_2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 2e 20 43 6f 6e 74 61 63 74 20 61 74 74 61 63 6b 65 72 } //1 Your files have been encrypted. Contact attacker
		$a_81_3 = {52 61 6e 73 6f 6d 20 6e 6f 74 65 20 73 65 6e 74 20 74 6f 20 70 72 69 6e 74 65 72 73 } //1 Ransom note sent to printers
		$a_81_4 = {64 69 73 6b 73 68 61 64 6f 77 5f 73 63 72 69 70 74 2e 74 78 74 } //1 diskshadow_script.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}