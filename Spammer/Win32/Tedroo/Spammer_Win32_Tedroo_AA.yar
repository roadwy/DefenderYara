
rule Spammer_Win32_Tedroo_AA{
	meta:
		description = "Spammer:Win32/Tedroo.AA,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {8a d0 80 c2 54 30 14 08 40 3b c6 72 f3 } //4
		$a_01_1 = {24 51 4d 5f 4d 45 53 53 49 44 } //1 $QM_MESSID
		$a_01_2 = {75 70 64 61 74 65 25 64 25 73 } //1 update%d%s
		$a_01_3 = {2f 73 70 6d 2f } //1 /spm/
		$a_01_4 = {5f 69 64 2e 64 61 74 } //1 _id.dat
		$a_01_5 = {3c 2f 63 6f 6e 66 69 67 3e } //1 </config>
		$a_01_6 = {24 54 4f 5f 45 4d 41 49 4c } //1 $TO_EMAIL
		$a_01_7 = {26 73 6d 74 70 3d 25 73 26 74 61 73 6b 3d 25 64 } //1 &smtp=%s&task=%d
		$a_01_8 = {67 65 74 5f 69 64 2e 70 68 70 } //1 get_id.php
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}