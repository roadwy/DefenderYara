
rule Trojan_Win64_DonutLoader_MK_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,6e 00 6e 00 07 00 00 "
		
	strings :
		$a_01_0 = {5b 20 53 68 65 6c 6c 63 6f 64 65 20 20 20 20 20 3a 20 22 25 73 22 } //20 [ Shellcode     : "%s"
		$a_01_1 = {5b 20 44 65 63 6f 79 20 70 61 74 68 20 20 20 20 3a 20 25 73 } //20 [ Decoy path    : %s
		$a_01_2 = {5b 20 54 61 72 67 65 74 20 43 50 55 20 20 20 20 3a 20 25 73 } //20 [ Target CPU    : %s
		$a_01_3 = {5b 20 41 4d 53 49 2f 57 44 4c 50 2f 45 54 57 20 3a 20 25 73 } //15 [ AMSI/WDLP/ETW : %s
		$a_01_4 = {44 6f 6e 75 74 20 73 68 65 6c 6c 63 6f 64 65 } //15 Donut shellcode
		$a_01_5 = {52 61 6e 64 6f 6d 20 6e 61 6d 65 73 20 2b 20 45 6e 63 72 79 70 74 69 6f 6e } //10 Random names + Encryption
		$a_01_6 = {4f 6e 6c 79 20 74 68 65 20 66 69 6e 65 73 74 20 61 72 74 69 73 61 6e 61 6c 20 64 6f 6e 75 74 73 20 61 72 65 20 6d 61 64 65 20 6f 66 20 73 68 65 6c 6c 73 2e } //10 Only the finest artisanal donuts are made of shells.
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_01_2  & 1)*20+(#a_01_3  & 1)*15+(#a_01_4  & 1)*15+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10) >=110
 
}