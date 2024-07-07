
rule Trojan_Win64_IcedID_AK_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {3f 67 6b 65 72 74 79 40 40 59 41 48 58 5a } //?gkerty@@YAHXZ  3
		$a_80_1 = {3f 72 6f 70 71 66 40 40 59 41 48 58 5a } //?ropqf@@YAHXZ  3
		$a_80_2 = {3f 73 6f 72 74 65 40 40 59 41 48 58 5a } //?sorte@@YAHXZ  3
		$a_80_3 = {4b 69 6c 6c 54 69 6d 65 72 } //KillTimer  3
		$a_80_4 = {47 65 74 4d 65 73 73 61 67 65 57 } //GetMessageW  3
		$a_80_5 = {53 65 6e 64 4d 65 73 73 61 67 65 57 } //SendMessageW  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=18
 
}