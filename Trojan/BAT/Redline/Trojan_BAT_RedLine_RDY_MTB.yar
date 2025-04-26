
rule Trojan_BAT_RedLine_RDY_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 63 31 64 62 33 33 32 2d 37 62 32 39 2d 34 63 66 66 2d 61 31 39 34 2d 62 64 62 35 66 62 36 61 36 30 35 37 } //1 0c1db332-7b29-4cff-a194-bdb5fb6a6057
		$a_01_1 = {37 30 33 39 5f 65 78 65 5f 68 61 72 64 77 61 72 65 5f 68 6f 73 70 69 74 61 6c 5f 69 6e 73 74 61 6c 6c 5f 69 6e 73 74 61 6c 6c 65 72 5f 69 63 6f 6e } //1 7039_exe_hardware_hospital_install_installer_icon
		$a_01_2 = {6b 36 58 5a 72 57 49 6f 79 41 72 57 58 51 70 44 51 6f 2e 44 66 42 37 53 6e 32 35 72 37 68 4e 70 34 45 42 4b 57 } //1 k6XZrWIoyArWXQpDQo.DfB7Sn25r7hNp4EBKW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}