
rule PWS_BAT_Mercurial_GA_MTB{
	meta:
		description = "PWS:BAT/Mercurial.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 0c 00 00 "
		
	strings :
		$a_80_0 = {2d 20 6d 65 72 63 75 72 69 61 6c 20 67 72 61 62 62 65 72 20 2d } //- mercurial grabber -  10
		$a_80_1 = {53 74 65 61 6c 65 72 } //Stealer  10
		$a_80_2 = {47 72 61 62 62 65 72 } //Grabber  1
		$a_80_3 = {52 6f 62 6c 6f 78 } //Roblox  1
		$a_80_4 = {44 65 74 65 63 74 44 65 62 75 67 } //DetectDebug  1
		$a_80_5 = {4d 69 6e 65 63 72 61 66 74 } //Minecraft  1
		$a_80_6 = {76 6d 77 61 72 65 } //vmware  1
		$a_80_7 = {76 69 72 74 75 61 6c 62 6f 78 } //virtualbox  1
		$a_80_8 = {43 61 70 74 75 72 65 2e 6a 70 67 } //Capture.jpg  1
		$a_80_9 = {5c 63 6f 6f 6b 69 65 73 2e 74 78 74 } //\cookies.txt  1
		$a_80_10 = {70 61 73 73 77 6f 72 64 73 2e 74 78 74 } //passwords.txt  1
		$a_80_11 = {70 68 6f 6e 65 } //phone  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=28
 
}