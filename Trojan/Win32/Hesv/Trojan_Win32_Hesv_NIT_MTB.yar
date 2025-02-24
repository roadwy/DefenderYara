
rule Trojan_Win32_Hesv_NIT_MTB{
	meta:
		description = "Trojan:Win32/Hesv.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 2e 62 61 74 } //2 start.bat
		$a_01_1 = {5f 5f 74 6d 70 5f 72 61 72 5f 73 66 78 5f 61 63 63 65 73 73 5f 63 68 65 63 6b 5f 25 75 } //2 __tmp_rar_sfx_access_check_%u
		$a_01_2 = {75 6e 6b 6e 6f 77 6e 64 6c 6c 2e 70 64 62 } //2 unknowndll.pdb
		$a_01_3 = {4b 4a 4f 5f 55 50 44 41 54 45 5c 6b 6a 6f 5f 75 70 64 61 74 65 2e 62 61 74 } //1 KJO_UPDATE\kjo_update.bat
		$a_01_4 = {4b 4a 4f 5f 55 50 44 41 54 45 5c 77 67 65 74 2e 65 78 65 } //1 KJO_UPDATE\wget.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}