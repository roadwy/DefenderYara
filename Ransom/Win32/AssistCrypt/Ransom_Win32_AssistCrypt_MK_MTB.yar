
rule Ransom_Win32_AssistCrypt_MK_MTB{
	meta:
		description = "Ransom:Win32/AssistCrypt.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 06 00 00 "
		
	strings :
		$a_81_0 = {40 2e 61 73 73 69 73 74 } //10 @.assist
		$a_81_1 = {61 73 73 69 73 74 2e 69 6e 69 } //10 assist.ini
		$a_81_2 = {63 6d 64 2e 65 78 65 20 2f 43 20 70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e 20 31 20 2d 77 } //5 cmd.exe /C ping 1.1.1.1 -n 1 -w
		$a_81_3 = {45 78 74 3d 6c 6f 67 7c 6c 6f 67 31 7c 6c 6f 67 32 7c 74 6d 70 7c 73 79 73 7c 62 6f 6f 74 6d 67 72 7c 64 6c 6c 7c 74 68 65 6d 65 7c 62 61 74 7c 63 6d 64 7c 67 64 63 62 } //10 Ext=log|log1|log2|tmp|sys|bootmgr|dll|theme|bat|cmd|gdcb
		$a_81_4 = {50 72 63 3d 77 33 77 70 7c 73 71 6c 7c 65 78 63 68 61 6e 7c 6e 6f 64 65 7c 73 63 61 6e 7c 6f 75 74 6c 6f 6f 6b 7c 74 68 65 62 61 74 7c 63 68 72 6f 6d 65 7c 66 69 72 65 66 6f 78 } //10 Prc=w3wp|sql|exchan|node|scan|outlook|thebat|chrome|firefox
		$a_81_5 = {46 4e 61 6d 65 3d 41 53 53 49 53 54 2d 52 45 41 44 4d 45 2e 74 78 74 } //10 FName=ASSIST-README.txt
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*5+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10) >=55
 
}