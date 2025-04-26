
rule Trojan_AndroidOS_Basdoor_A{
	meta:
		description = "Trojan:AndroidOS/Basdoor.A,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 75 70 5f 66 69 6c 65 32 2e 70 68 70 } //2 /up_file2.php
		$a_00_1 = {26 73 65 6e 64 73 6d 73 3d } //2 &sendsms=
		$a_00_2 = {26 61 63 74 69 6f 6e 3d 62 6c 69 73 74 } //2 &action=blist
		$a_00_3 = {73 6d 62 6f 6d 62 65 72 } //2 smbomber
		$a_00_4 = {26 61 64 6d 69 6e 6e 3d } //2 &adminn=
		$a_00_5 = {26 61 63 74 69 6f 6e 3d 61 6c 6c 61 70 70 } //2 &action=allapp
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2) >=12
 
}