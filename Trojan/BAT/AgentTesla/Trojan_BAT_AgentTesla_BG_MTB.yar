
rule Trojan_BAT_AgentTesla_BG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 72 6f 67 72 61 6d 31 74 61 6e 6e 6f 74 20 62 76 31 72 75 6e 20 69 6e 20 55 60 53 20 6d 6f 64 65 } //1 program1tannot bv1run in U`S mode
		$a_01_1 = {6b 65 72 6e 65 6c 33 43 3f 64 6c 6c } //1 kernel3C?dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_BG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {69 00 63 00 61 00 6e 00 68 00 61 00 7a 00 69 00 70 00 2e 00 63 00 6f 00 6d 00 } //1 icanhazip.com
		$a_01_1 = {4d 00 6f 00 6f 00 6c 00 69 00 76 00 65 00 2e 00 65 00 78 00 65 00 } //1 Moolive.exe
		$a_01_2 = {46 00 69 00 6e 00 64 00 76 00 69 00 72 00 75 00 2e 00 65 00 78 00 65 00 } //1 Findviru.exe
		$a_01_3 = {76 00 6d 00 77 00 61 00 72 00 65 00 } //1 vmware
		$a_01_4 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 42 00 6f 00 78 00 } //1 VirtualBox
		$a_01_5 = {4a 00 65 00 64 00 69 00 2e 00 65 00 78 00 65 00 } //1 Jedi.exe
		$a_01_6 = {24 33 43 33 37 34 41 34 32 2d 42 41 45 34 2d 31 31 43 46 2d 42 46 37 44 2d 30 30 41 41 30 30 36 39 34 36 45 45 } //1 $3C374A42-BAE4-11CF-BF7D-00AA006946EE
		$a_01_7 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 } //1 Select * from Win32_ComputerSystem
		$a_01_8 = {50 00 4b 00 31 00 31 00 53 00 44 00 52 00 5f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 } //1 PK11SDR_Decrypt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}