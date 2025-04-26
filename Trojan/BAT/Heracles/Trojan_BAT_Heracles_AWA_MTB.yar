
rule Trojan_BAT_Heracles_AWA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AWA!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 72 68 73 56 70 6b 78 77 7a 52 4c 69 48 6c 63 48 61 6f 51 4c 4e 79 61 63 2e 64 6c 6c } //2 PrhsVpkxwzRLiHlcHaoQLNyac.dll
		$a_01_1 = {48 41 70 51 67 76 6a 7a 53 79 64 72 6c 6d 50 62 78 50 50 6e 78 65 64 2e 64 6c 6c } //2 HApQgvjzSydrlmPbxPPnxed.dll
		$a_01_2 = {64 6d 55 47 4d 6a 7a 45 6f 4c 78 6c 6b 65 76 45 4b 51 4c 6c 72 48 65 65 6b 70 50 44 4d 2e 64 6c 6c } //2 dmUGMjzEoLxlkevEKQLlrHeekpPDM.dll
		$a_01_3 = {73 64 6f 41 57 4f 71 53 6d 77 49 71 68 4d 47 77 78 70 46 56 75 48 2e 64 6c 6c } //2 sdoAWOqSmwIqhMGwxpFVuH.dll
		$a_01_4 = {66 54 59 49 47 62 70 48 6f 64 63 42 59 46 43 47 49 75 53 79 6e 47 4b 2e 64 6c 6c } //2 fTYIGbpHodcBYFCGIuSynGK.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}