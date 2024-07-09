
rule Backdoor_Linux_Gafgyt_F{
	meta:
		description = "Backdoor:Linux/Gafgyt.F,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {42 6f 61 74 6e 65 74 } //1 Boatnet
		$a_00_1 = {73 65 6c 66 20 72 65 70 20 6e 65 74 69 73 20 61 6e 64 20 6e 72 70 65 20 67 6f 74 } //1 self rep netis and nrpe got
		$a_00_2 = {38 30 2e 32 31 31 2e 37 35 2e 33 35 } //2 80.211.75.35
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2) >=4
 
}
rule Backdoor_Linux_Gafgyt_F_2{
	meta:
		description = "Backdoor:Linux/Gafgyt.F,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {68 75 61 77 65 69 5f 6b 69 6c 6c } //huawei_kill  1
		$a_80_1 = {3c 4e 65 77 53 74 61 74 75 73 55 52 4c 3e 24 28 2f 62 69 6e 2f 62 75 73 79 62 6f 78 20 77 67 65 74 20 2d 67 } //<NewStatusURL>$(/bin/busybox wget -g  1
		$a_80_2 = {3c 4e 65 77 44 6f 77 6e 6c 6f 61 64 55 52 4c 3e 24 28 65 63 68 6f 20 48 55 41 57 45 49 55 50 4e 50 29 3c 2f 4e 65 77 44 6f 77 6e 6c 6f 61 64 55 52 4c 3e } //<NewDownloadURL>$(echo HUAWEIUPNP)</NewDownloadURL>  1
		$a_03_3 = {31 c0 ff c0 80 75 00 ?? 48 ff c5 41 39 c4 75 f2 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}