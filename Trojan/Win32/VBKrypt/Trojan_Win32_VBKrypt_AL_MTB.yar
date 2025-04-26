
rule Trojan_Win32_VBKrypt_AL_MTB{
	meta:
		description = "Trojan:Win32/VBKrypt.AL!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {45 6b 73 74 65 72 6e 61 74 65 72 } //1 Eksternater
		$a_01_1 = {53 75 70 65 72 63 6c 61 69 6d 32 } //1 Superclaim2
		$a_01_2 = {46 49 4c 4d 41 54 45 4c 49 45 52 45 52 } //1 FILMATELIERER
		$a_01_3 = {46 61 63 65 73 68 65 65 74 73 } //1 Facesheets
		$a_01_4 = {73 74 61 6d 70 75 62 6c 69 6b 75 6d 6d 65 72 73 } //1 stampublikummers
		$a_01_5 = {53 4d 49 4c 45 48 55 4c 4c 45 52 } //1 SMILEHULLER
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}