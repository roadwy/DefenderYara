
rule Backdoor_WinNT_Trupto_A_MTB{
	meta:
		description = "Backdoor:WinNT/Trupto.A!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 72 6f 73 73 72 61 74 2f 63 6c 69 65 6e 74 } //1 crossrat/client
		$a_00_1 = {6d 65 64 69 61 6d 67 72 73 2e 6a 61 72 } //1 mediamgrs.jar
		$a_00_2 = {6f 72 67 2f 61 2f 61 2f 61 2f 62 } //1 org/a/a/a/b
		$a_00_3 = {6f 73 2e 6e 61 6d 65 } //1 os.name
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}