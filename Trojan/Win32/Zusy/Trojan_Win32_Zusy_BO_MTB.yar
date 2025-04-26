
rule Trojan_Win32_Zusy_BO_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 73 6f 69 6a 68 67 69 72 6f 64 41 6f 73 66 6a 68 72 68 72 } //2 CsoijhgirodAosfjhrhr
		$a_01_1 = {4b 73 64 67 6f 77 73 72 6a 68 73 69 72 6a 68 73 72 68 6a } //2 Ksdgowsrjhsirjhsrhj
		$a_01_2 = {4c 73 68 64 67 73 69 6b 64 6a 67 6f 69 51 6a 73 66 6f 68 6a 66 } //2 LshdgsikdjgoiQjsfohjf
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}