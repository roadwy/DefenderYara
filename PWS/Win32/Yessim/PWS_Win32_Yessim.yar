
rule PWS_Win32_Yessim{
	meta:
		description = "PWS:Win32/Yessim,SIGNATURE_TYPE_PEHSTR,0c 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {5c 64 69 73 6b 72 65 6d 6f 76 61 62 6c 65 } //1 \diskremovable
		$a_01_1 = {5c 64 69 73 6b 66 69 78 65 64 } //1 \diskfixed
		$a_01_2 = {4b 65 79 4c 6f 67 67 65 72 } //1 KeyLogger
		$a_01_3 = {5b 43 4d 44 5d 5b 54 52 41 43 4b 20 53 49 54 45 5d 2d 3e } //2 [CMD][TRACK SITE]->
		$a_01_4 = {5b 4b 45 59 4c 4f 47 20 52 45 54 52 49 45 56 45 52 5d 2d 3e } //2 [KEYLOG RETRIEVER]->
		$a_01_5 = {73 69 6d 00 79 65 73 00 } //5 楳m敹s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*5) >=9
 
}