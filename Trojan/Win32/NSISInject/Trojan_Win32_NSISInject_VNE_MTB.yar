
rule Trojan_Win32_NSISInject_VNE_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.VNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {69 6e 61 6e 69 74 79 2e 65 78 65 } //1 inanity.exe
		$a_81_1 = {68 61 68 6e 65 6d 61 6e 6e 69 61 6e 20 6d 61 6c 61 79 73 69 73 6b } //1 hahnemannian malaysisk
		$a_81_2 = {6d 6f 72 61 74 6f 72 69 75 6d 20 66 6c 61 6e 6b 65 72 69 6e 67 65 72 20 73 74 75 64 69 65 6b 72 65 64 73 65 6e 65 73 } //1 moratorium flankeringer studiekredsenes
		$a_81_3 = {75 64 73 61 76 6e 69 6e 67 } //1 udsavning
		$a_81_4 = {31 64 31 68 31 6c 31 70 31 74 31 78 31 7c 31 } //1 1d1h1l1p1t1x1|1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}