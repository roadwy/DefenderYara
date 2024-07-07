
rule Trojan_Win32_Ursnif_GNQ_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 10 0f b6 04 97 66 31 04 91 8b 54 24 20 8a ca 8b 44 24 14 80 f1 69 02 4c 70 0a } //10
		$a_01_1 = {73 74 77 6e 34 30 34 79 61 31 33 2e 64 6c 6c } //1 stwn404ya13.dll
		$a_01_2 = {50 46 72 64 6e 65 35 52 4c } //1 PFrdne5RL
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}