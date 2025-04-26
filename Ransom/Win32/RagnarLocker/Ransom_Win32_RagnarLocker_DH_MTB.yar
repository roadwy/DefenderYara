
rule Ransom_Win32_RagnarLocker_DH_MTB{
	meta:
		description = "Ransom:Win32/RagnarLocker.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {2e 72 61 67 6e 61 72 6f 6b } //1 .ragnarok
		$a_81_1 = {63 6d 64 2e 65 78 65 20 2f 63 20 76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //1 cmd.exe /c vssadmin delete shadows /all /quiet
		$a_81_2 = {43 3a 5c 61 61 61 5f 54 6f 75 63 68 4d 65 4e 6f 74 5f 5c 61 61 61 5f 54 6f 75 63 68 4d 65 4e 6f 74 5f 2e 74 78 74 } //1 C:\aaa_TouchMeNot_\aaa_TouchMeNot_.txt
		$a_01_3 = {43 00 3a 00 5c 00 4d 00 69 00 72 00 63 00 5c 00 48 00 6f 00 77 00 5f 00 54 00 6f 00 5f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 5f 00 4d 00 79 00 5f 00 46 00 69 00 6c 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //1 C:\Mirc\How_To_Decrypt_My_Files.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}