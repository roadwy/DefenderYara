
rule Trojan_Win32_MammonRansom_YAN_MTB{
	meta:
		description = "Trojan:Win32/MammonRansom.YAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 67 6f 6f 64 6c 75 63 6b } //1 .goodluck
		$a_01_1 = {43 3a 5c 4b 65 79 6c 6f 63 6b 5c 69 64 2e 74 78 74 } //1 C:\Keylock\id.txt
		$a_01_2 = {43 3a 5c 4b 65 79 6c 6f 63 6b 5c 70 62 2e 74 78 74 } //1 C:\Keylock\pb.txt
		$a_01_3 = {4b 65 79 6c 6f 63 6b 5c 6b 79 2e 44 41 54 } //1 Keylock\ky.DAT
		$a_01_4 = {47 3a 5c 4d 61 6d 6d 6f 6e 5c 52 65 6c 65 61 73 65 5c 4d 61 6d 6d 6f 6e 2e 70 64 62 } //10 G:\Mammon\Release\Mammon.pdb
		$a_03_5 = {69 6e 20 63 61 73 65 20 6f 66 20 6e 6f 20 61 6e 73 77 65 72 20 62 61 63 6b 75 70 20 65 6d 61 69 6c 3a [0-20] 40 67 6d 61 69 6c 2e 63 6f 6d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*10+(#a_03_5  & 1)*1) >=10
 
}