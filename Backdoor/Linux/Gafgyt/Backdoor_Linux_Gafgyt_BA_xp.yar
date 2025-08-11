
rule Backdoor_Linux_Gafgyt_BA_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BA!xp,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 72 65 61 6d 62 6f 78 } //2 dreambox
		$a_01_1 = {78 6d 68 64 69 70 63 } //2 xmhdipc
		$a_01_2 = {61 64 6d 69 6e 31 32 33 34 } //1 admin1234
		$a_01_3 = {6b 6c 76 31 32 33 } //1 klv123
		$a_01_4 = {63 6f 6d 2e 62 69 74 64 65 66 65 6e 64 65 72 } //-1 com.bitdefender
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*-1) >=6
 
}