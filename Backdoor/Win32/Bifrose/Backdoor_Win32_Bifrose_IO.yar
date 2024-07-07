
rule Backdoor_Win32_Bifrose_IO{
	meta:
		description = "Backdoor:Win32/Bifrose.IO,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 6d 00 6f 00 6e 00 73 00 74 00 65 00 72 00 6d 00 6f 00 20 00 6e 00 73 00 74 00 20 00 65 00 72 00 6d 00 6f 00 6e 00 73 00 74 00 65 00 5c 00 6d 00 6f 00 6e 00 73 00 74 00 65 00 72 00 6d 00 6f 00 6e 00 73 00 74 00 65 00 5c 00 72 00 6d 00 6f 00 6e 00 73 00 74 00 65 00 72 00 6d 00 6f 00 5c 00 6e 00 73 00 74 00 65 00 72 00 6d 00 20 00 6f 00 6e 00 73 00 5c 00 74 00 65 00 72 00 6d 00 6f 00 6e 00 73 00 74 00 65 00 72 00 6d 00 6f 00 6e 00 73 00 2e 00 76 00 62 00 70 00 } //1 C:\monstermo nst ermonste\monstermonste\rmonstermo\nsterm ons\termonstermons.vbp
	condition:
		((#a_01_0  & 1)*1) >=1
 
}