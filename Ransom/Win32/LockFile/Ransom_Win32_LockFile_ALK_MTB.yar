
rule Ransom_Win32_LockFile_ALK_MTB{
	meta:
		description = "Ransom:Win32/LockFile.ALK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f bd f7 0f bd d1 83 f6 1f 83 f2 1f 83 ce 20 80 7c 24 10 00 0f 44 d6 0f bd f3 0f bd c8 83 f6 1f 83 f1 1f 83 ce 20 85 c0 0f 45 f1 83 ce 40 0b 7c 24 08 0f 45 f2 6a 7b 5f 29 f7 } //3
		$a_01_1 = {59 6f 75 72 20 69 6e 66 72 61 73 74 72 75 63 74 75 72 65 20 44 65 61 64 4c 6f 63 6b 65 64 } //2 Your infrastructure DeadLocked
		$a_01_2 = {41 6c 6c 20 46 69 6c 65 73 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //1 All Files stolen and encrypted
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}