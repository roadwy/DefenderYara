
rule Backdoor_BAT_Hamaetot_A{
	meta:
		description = "Backdoor:BAT/Hamaetot.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 00 74 00 61 00 72 00 74 00 6b 00 6c 00 } //1 startkl
		$a_01_1 = {6c 00 64 00 6f 00 73 00 } //1 ldos
		$a_01_2 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 78 00 65 00 } //1 downloadexe
		$a_01_3 = {26 00 72 00 65 00 63 00 65 00 69 00 76 00 65 00 3d 00 75 00 70 00 6c 00 6f 00 61 00 64 00 26 00 75 00 70 00 6c 00 6f 00 61 00 64 00 74 00 79 00 70 00 65 00 3d 00 75 00 66 00 69 00 6c 00 65 00 26 00 66 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 3d 00 } //1 &receive=upload&uploadtype=ufile&filename=
		$a_01_4 = {26 00 72 00 65 00 63 00 65 00 69 00 76 00 65 00 3d 00 75 00 70 00 6c 00 6f 00 61 00 64 00 26 00 75 00 70 00 6c 00 6f 00 61 00 64 00 74 00 79 00 70 00 65 00 3d 00 73 00 63 00 72 00 65 00 65 00 6e 00 26 00 66 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 3d 00 73 00 63 00 72 00 65 00 65 00 6e 00 2e 00 70 00 6e 00 67 00 } //1 &receive=upload&uploadtype=screen&filename=screen.png
		$a_01_5 = {26 00 72 00 65 00 63 00 65 00 69 00 76 00 65 00 3d 00 75 00 70 00 6c 00 6f 00 61 00 64 00 26 00 75 00 70 00 6c 00 6f 00 61 00 64 00 74 00 79 00 70 00 65 00 3d 00 77 00 65 00 62 00 63 00 61 00 6d 00 26 00 66 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 3d 00 77 00 65 00 62 00 63 00 61 00 6d 00 2e 00 6a 00 70 00 67 00 } //1 &receive=upload&uploadtype=webcam&filename=webcam.jpg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}