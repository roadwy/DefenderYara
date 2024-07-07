
rule Backdoor_Linux_Gafgyt_BI_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BI!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 62 75 73 79 62 6f 78 } //1 /bin/busybox
		$a_01_1 = {2d 6c 6f 6c 64 6f 6e 67 73 } //1 -loldongs
		$a_01_2 = {53 45 52 56 5a 55 58 4f } //1 SERVZUXO
		$a_01_3 = {78 34 37 72 6f 75 70 73 3a 09 30 } //1
		$a_01_4 = {2f 64 65 76 2f 6e 75 6c 6c } //1 /dev/null
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}