
rule Trojan_Linux_Ddostf_Dx_xp{
	meta:
		description = "Trojan:Linux/Ddostf.Dx!xp,SIGNATURE_TYPE_ELFHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 57 56 53 81 ec c8 00 00 00 8d 5d c4 c7 45 cc 00 00 00 00 c7 45 d0 00 00 00 00 a1 a4 a1 0c 08 66 c1 c8 08 66 89 45 c6 66 c7 45 c4 02 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 c8 83 c4 0c 6a 00 6a 01 6a 02 e8 ?? ?? ?? ?? 89 c6 } //5
		$a_00_1 = {55 44 50 2d 46 6c 6f 77 } //1 UDP-Flow
		$a_00_2 = {53 59 4e 2d 46 6c 6f 77 } //1 SYN-Flow
		$a_00_3 = {62 58 6c 7a 63 79 35 69 59 58 4e 6c 59 79 35 6a 59 77 3d 3d } //1 bXlzcy5iYXNlYy5jYw==
		$a_00_4 = {76 61 72 2f 72 75 6e 2f 6b 6c 73 73 2e 70 69 64 } //1 var/run/klss.pid
		$a_00_5 = {2f 76 61 72 2f 74 6d 70 2f 74 65 73 74 2e 6c 6f 67 } //1 /var/tmp/test.log
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=9
 
}