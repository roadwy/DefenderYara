
rule Trojan_BAT_CryptInject_PC_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 61 36 30 63 63 33 37 38 2d 62 31 30 61 2d 34 66 66 32 2d 38 30 33 61 2d 35 36 39 31 30 34 31 32 62 34 33 37 } //1 $a60cc378-b10a-4ff2-803a-56910412b437
		$a_81_1 = {50 6c 61 6e 65 47 61 6d 65 } //1 PlaneGame
		$a_81_2 = {67 65 74 5f 4d 64 69 43 68 69 6c 64 72 65 6e } //1 get_MdiChildren
		$a_81_3 = {73 65 74 5f 4d 64 69 50 61 72 65 6e 74 } //1 set_MdiParent
		$a_81_4 = {50 6c 61 6e 65 50 61 72 65 6e 74 } //1 PlaneParent
		$a_81_5 = {4d 44 49 50 61 72 65 6e 74 31 } //1 MDIParent1
		$a_81_6 = {50 6c 61 6e 65 47 61 6d 65 2e 4d 44 49 50 61 72 65 6e 74 31 2e 72 65 73 6f 75 72 63 65 73 } //1 PlaneGame.MDIParent1.resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}