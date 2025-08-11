
rule Trojan_Win32_Guloader_AQ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {69 6e 74 65 72 72 75 70 74 6f 72 79 5c 64 72 69 66 74 73 63 68 65 66 73 2e 7a 69 70 } //1 interruptory\driftschefs.zip
		$a_81_1 = {62 72 75 67 65 72 64 69 73 63 69 70 6c 69 6e 65 6e 5c 61 6b 74 75 61 72 65 6e 2e 74 78 74 } //1 brugerdisciplinen\aktuaren.txt
		$a_81_2 = {66 61 63 6f 6e 73 74 61 61 6c 65 74 5c 67 75 61 68 69 62 61 6e } //1 faconstaalet\guahiban
		$a_81_3 = {69 6d 6d 61 74 75 72 65 73 5c 64 69 76 69 64 65 72 65 72 5c 70 61 6c 65 6f 73 74 79 6c 69 63 } //1 immatures\dividerer\paleostylic
		$a_81_4 = {6d 6f 6e 6f 75 72 65 69 64 65 2e 62 69 6e } //1 monoureide.bin
		$a_81_5 = {73 75 62 74 69 6c 69 73 65 64 5c 65 73 71 75 69 6c 69 6e 65 2e 69 6e 69 } //1 subtilised\esquiline.ini
		$a_81_6 = {6c 79 63 6f 70 65 72 64 6f 6e 2e 63 79 6c } //1 lycoperdon.cyl
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}