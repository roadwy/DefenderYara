
rule Trojan_Win32_Amadey_AHUG_MTB{
	meta:
		description = "Trojan:Win32/Amadey.AHUG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 00 ff d6 6a 00 6a 00 ff d7 4b } //2
		$a_01_1 = {4f 70 65 6e 4d 75 74 65 78 57 } //1 OpenMutexW
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}