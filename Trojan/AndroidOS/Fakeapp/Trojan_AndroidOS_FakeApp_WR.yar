
rule Trojan_AndroidOS_FakeApp_WR{
	meta:
		description = "Trojan:AndroidOS/FakeApp.WR,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 6c 39 4e 47 46 41 5a 56 31 70 41 56 78 73 49 45 77 34 46 51 6d 41 3d } //1 Ll9NGFAZV1pAVxsIEw4FQmA=
		$a_01_1 = {4c 6b 56 55 57 6c 52 4c 59 31 4a 42 51 51 38 54 44 68 67 3d } //1 LkVUWlRLY1JBQQ8TDhg=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}