
rule Trojan_Win32_FormBook_QE_MTB{
	meta:
		description = "Trojan:Win32/FormBook.QE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {75 6e 63 61 6e 6e 79 2e 62 61 74 } //3 uncanny.bat
		$a_81_1 = {7a 63 6e 6f 75 76 74 70 64 72 64 6d } //3 zcnouvtpdrdm
		$a_81_2 = {74 6d 70 5c 6d 61 61 75 61 74 71 67 63 79 2e 64 6c 6c } //3 tmp\maauatqgcy.dll
		$a_81_3 = {6f 70 63 5f 70 61 63 6b 61 67 65 5f 77 72 69 74 65 } //3 opc_package_write
		$a_81_4 = {46 6d 74 49 64 54 6f 50 72 6f 70 53 74 67 4e 61 6d 65 } //3 FmtIdToPropStgName
		$a_81_5 = {55 74 47 65 74 44 76 74 64 31 36 49 6e 66 6f } //3 UtGetDvtd16Info
		$a_81_6 = {76 78 66 76 61 63 66 } //3 vxfvacf
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}