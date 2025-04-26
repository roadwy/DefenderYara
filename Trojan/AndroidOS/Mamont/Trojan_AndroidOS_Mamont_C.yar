
rule Trojan_AndroidOS_Mamont_C{
	meta:
		description = "Trojan:AndroidOS/Mamont.C,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 64 73 6d 73 2f 41 75 74 6f 43 6c 69 63 6b 53 65 72 76 69 63 65 } //2 sendsms/AutoClickService
		$a_01_1 = {2f 65 72 72 2e 70 68 70 3f 69 31 3d } //2 /err.php?i1=
		$a_01_2 = {2f 6e 65 65 64 65 64 2e 70 68 70 3f 69 31 3d } //2 /needed.php?i1=
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}