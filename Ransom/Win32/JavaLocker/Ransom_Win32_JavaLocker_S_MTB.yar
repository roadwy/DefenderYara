
rule Ransom_Win32_JavaLocker_S_MTB{
	meta:
		description = "Ransom:Win32/JavaLocker.S!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 6a 61 76 61 6c 6f 63 6b 65 72 } //1 .javalocker
		$a_00_1 = {5c 72 65 61 64 6d 65 6f 6e 6e 6f 74 65 70 61 64 2e 6a 61 76 61 65 6e 63 72 79 70 74 } //1 \readmeonnotepad.javaencrypt
		$a_00_2 = {57 68 61 74 20 48 61 70 70 65 6e 20 74 6f 20 6d 79 20 63 6f 6d 70 75 74 65 72 3f } //1 What Happen to my computer?
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}