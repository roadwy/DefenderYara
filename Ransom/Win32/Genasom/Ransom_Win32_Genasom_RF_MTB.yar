
rule Ransom_Win32_Genasom_RF_MTB{
	meta:
		description = "Ransom:Win32/Genasom.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 45 41 52 43 52 59 21 } //1 DEARCRY!
		$a_01_1 = {72 65 61 64 6d 65 2e 74 78 74 } //1 readme.txt
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 21 } //1 Your file has been encrypted!
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 6a 6f 68 6e 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 30 38 5c 50 72 6f 6a 65 63 74 73 5c 45 6e 63 72 79 70 74 46 69 6c 65 20 2d 73 76 63 56 32 5c 52 65 6c 65 61 73 65 5c 45 6e 63 72 79 70 74 46 69 6c 65 2e 65 78 65 2e 70 64 62 } //1 C:\Users\john\Documents\Visual Studio 2008\Projects\EncryptFile -svcV2\Release\EncryptFile.exe.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}