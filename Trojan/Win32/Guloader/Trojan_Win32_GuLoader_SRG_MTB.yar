
rule Trojan_Win32_GuLoader_SRG_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SRG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 55 6e 62 65 69 6e 67 35 35 5c 6b 72 6f 65 72 5c 74 69 6e 67 69 64 } //1 \Unbeing55\kroer\tingid
		$a_81_1 = {42 6f 73 74 65 64 65 72 35 2e 73 6f 63 } //1 Bosteder5.soc
		$a_81_2 = {46 69 6c 73 74 72 75 6b 74 75 72 2e 74 78 74 } //1 Filstruktur.txt
		$a_81_3 = {63 6f 70 61 6c 69 6e 65 2e 75 6e 63 } //1 copaline.unc
		$a_81_4 = {64 65 73 74 65 6d 70 65 72 2e 74 78 74 } //1 destemper.txt
		$a_81_5 = {66 65 72 73 6b 65 2e 6b 61 70 } //1 ferske.kap
		$a_81_6 = {75 6e 64 65 72 67 69 76 65 6c 73 65 6e 73 2e 69 6e 69 } //1 undergivelsens.ini
		$a_81_7 = {5c 70 72 6f 63 74 6f 63 6c 79 73 69 73 5c 72 6f 73 65 74 61 6e 2e 66 69 73 } //1 \proctoclysis\rosetan.fis
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}