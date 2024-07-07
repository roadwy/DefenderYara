
rule Trojan_Win32_Frockafob_C{
	meta:
		description = "Trojan:Win32/Frockafob.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {54 72 69 63 6b 42 6f 74 43 6c 69 65 6e 74 45 78 65 2e 70 64 62 } //1 TrickBotClientExe.pdb
		$a_01_1 = {2f 35 30 2f 63 6d 64 3d } //1 /50/cmd=
		$a_01_2 = {53 75 63 63 73 65 66 75 6c 6c 79 20 65 78 65 63 75 74 65 64 3a } //1 Succsefully executed:
		$a_01_3 = {2f 63 61 6d 70 31 2f } //1 /camp1/
		$a_01_4 = {67 65 74 2d 66 69 6c 65 } //1 get-file
		$a_01_5 = {63 61 6c 6c 69 6e 67 20 70 75 74 20 66 69 6c 65 } //1 calling put file
		$a_01_6 = {54 72 69 63 6b 42 6f 74 2d 49 6d 70 6c 61 6e 74 } //1 TrickBot-Implant
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}