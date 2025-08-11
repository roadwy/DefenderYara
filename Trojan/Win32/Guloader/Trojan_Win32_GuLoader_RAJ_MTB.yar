
rule Trojan_Win32_GuLoader_RAJ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 63 6f 75 6e 74 65 72 63 72 69 74 69 63 69 73 6d 73 5c 65 72 65 63 74 6f 72 5c 68 65 6c 74 65 64 69 67 74 65 6e 65 } //1 \countercriticisms\erector\heltedigtene
		$a_81_1 = {6b 6f 6d 6d 75 6e 69 6b 61 74 69 6f 6e 73 6c 69 6e 69 65 72 2e 73 70 72 } //1 kommunikationslinier.spr
		$a_81_2 = {6b 6f 6e 74 72 61 73 74 65 72 69 6e 67 } //1 kontrastering
		$a_81_3 = {70 61 61 73 6b 72 69 66 74 65 6e 73 20 76 61 6e 64 74 69 6c 66 72 73 6c 65 6e } //1 paaskriftens vandtilfrslen
		$a_81_4 = {67 72 75 66 66 69 73 68 2e 65 78 65 } //1 gruffish.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}