
rule Trojan_Win32_Zenapak_CCCQ_MTB{
	meta:
		description = "Trojan:Win32/Zenapak.CCCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 00 69 00 66 00 65 00 71 00 67 00 6f 00 64 00 } //1 lifeqgod
		$a_01_1 = {68 00 61 00 74 00 68 00 74 00 5a 00 71 00 65 00 5a 00 6f 00 76 00 65 00 72 00 68 00 52 00 79 00 65 00 61 00 72 00 73 00 } //1 hathtZqeZoverhRyears
		$a_01_2 = {43 00 63 00 72 00 65 00 61 00 74 00 75 00 72 00 65 00 4d 00 77 00 65 00 72 00 65 00 44 00 30 00 32 00 6d 00 6f 00 76 00 69 00 6e 00 67 00 } //1 CcreatureMwereD02moving
		$a_01_3 = {73 00 56 00 55 00 6e 00 64 00 65 00 72 00 66 00 69 00 72 00 6d 00 61 00 6d 00 65 00 6e 00 74 00 } //1 sVUnderfirmament
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}