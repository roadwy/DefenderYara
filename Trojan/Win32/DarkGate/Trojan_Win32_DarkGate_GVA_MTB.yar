
rule Trojan_Win32_DarkGate_GVA_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 0d 00 ff ff ff 40 8b 4d 08 0f b6 14 01 8b 45 0c 03 45 fc 0f b6 08 33 ca 8b 55 0c 03 55 fc 88 0a } //3
		$a_01_1 = {40 8b 4d 08 88 81 00 01 00 00 8b 55 08 0f b6 82 01 01 00 00 8b 4d 08 0f b6 91 00 01 00 00 8b 4d 08 0f b6 14 11 03 c2 25 } //1
		$a_01_2 = {44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 } //1 DllGetClassObject
		$a_01_3 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 DllCanUnloadNow
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}