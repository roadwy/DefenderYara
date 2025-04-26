
rule Ransom_Win32_Mammon_YAB_MTB{
	meta:
		description = "Ransom:Win32/Mammon.YAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 "
		
	strings :
		$a_01_0 = {55 73 65 72 73 5c 41 64 6d 69 6e 5c 44 65 73 6b 74 6f 70 5c 4d 61 6d 6d 6f 6e 5c 52 65 6c 65 61 73 65 5c 4d 61 6d 6d 6f 6e 2e 70 64 62 } //10 Users\Admin\Desktop\Mammon\Release\Mammon.pdb
		$a_01_1 = {52 00 45 00 41 00 44 00 2e 00 74 00 78 00 74 00 } //1 READ.txt
		$a_01_2 = {52 00 53 00 41 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 4b 00 65 00 79 00 5c 00 4b 00 45 00 59 00 2e 00 44 00 41 00 54 00 } //1 RSADecryptKey\KEY.DAT
		$a_01_3 = {5d 00 2e 00 6d 00 61 00 6d 00 6d 00 6e 00 } //1 ].mammn
		$a_01_4 = {5d 00 49 00 44 00 2d 00 5b 00 } //1 ]ID-[
		$a_01_5 = {2e 00 4d 00 61 00 69 00 6c 00 2d 00 5b 00 } //1 .Mail-[
		$a_01_6 = {66 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 76 00 65 00 20 00 62 00 65 00 65 00 6e 00 20 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 } //1 files have been encrypted
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=16
 
}