
rule Trojan_BAT_Remcos_HK_MTB{
	meta:
		description = "Trojan:BAT/Remcos.HK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {24 66 64 37 39 64 38 39 34 2d 38 62 64 30 2d 34 33 32 63 2d 61 61 30 37 2d 62 64 32 35 39 39 34 64 38 31 33 37 } //1 $fd79d894-8bd0-432c-aa07-bd25994d8137
		$a_81_1 = {57 70 31 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Wp1.Form1.resources
		$a_81_2 = {74 65 6c 44 69 72 2e 52 65 73 6f 75 72 63 65 73 } //1 telDir.Resources
		$a_81_3 = {6e 6f 74 61 72 6f 62 6f 74 } //1 notarobot
		$a_81_4 = {67 65 74 5f 52 65 64 } //1 get_Red
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}