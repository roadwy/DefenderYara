
rule Trojan_Win64_Convagent_ARAZ_MTB{
	meta:
		description = "Trojan:Win64/Convagent.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 6d 65 73 73 61 67 65 46 72 6f 6d 48 65 6c 6c 2e 74 78 74 } //2 smessageFromHell.txt
		$a_01_1 = {4e 6f 6a 61 6e } //2 Nojan
		$a_01_2 = {4e 45 56 45 52 20 6f 70 65 6e 20 66 69 6c 65 73 20 66 72 6f 6d 20 73 74 72 61 6e 67 65 72 73 } //2 NEVER open files from strangers
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}