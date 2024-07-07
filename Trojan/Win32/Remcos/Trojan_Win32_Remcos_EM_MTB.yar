
rule Trojan_Win32_Remcos_EM_MTB{
	meta:
		description = "Trojan:Win32/Remcos.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {67 65 6f 70 6c 75 67 69 6e 2e 6e 65 74 2f 6a 73 6f 6e 2e 67 70 } //1 geoplugin.net/json.gp
		$a_81_1 = {73 79 73 69 6e 66 6f 2e 74 78 74 } //1 sysinfo.txt
		$a_81_2 = {45 6c 65 76 61 74 69 6f 6e 3a 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 21 6e 65 77 3a } //1 Elevation:Administrator!new:
		$a_81_3 = {75 70 64 61 74 65 2e 76 62 73 } //1 update.vbs
		$a_81_4 = {66 73 6f 2e 44 65 6c 65 74 65 46 69 6c 65 } //1 fso.DeleteFile
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}