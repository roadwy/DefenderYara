
rule Trojan_Win32_FlyStudio_CZ_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_81_0 = {5f 45 4c 5f 48 69 64 65 4f 77 6e 65 72 } //1 _EL_HideOwner
		$a_81_1 = {6a 66 55 6a 63 4f 70 6a 4f 6b 63 47 6c 66 4c 6c 66 4c 6c 66 4c 6b 64 4b 6c 66 4c 78 71 56 72 6c 4d 71 6d 4e 6d 6a 4b 6a 63 49 6f 69 54 68 64 56 } //5 jfUjcOpjOkcGlfLlfLlfLkdKlfLxqVrlMqmNmjKjcIoiThdV
		$a_81_2 = {4d 69 43 43 50 50 68 6f 74 6f 73 68 6f 70 20 49 43 43 20 70 72 6f 66 69 6c 65 } //5 MiCCPPhotoshop ICC profile
		$a_81_3 = {5c 64 6e 66 2e 65 78 65 } //1 \dnf.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*1) >=11
 
}