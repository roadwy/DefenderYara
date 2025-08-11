
rule Trojan_Win32_Tofsee_Z_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 61 64 65 72 5f 69 64 } //1 loader_id
		$a_01_1 = {73 74 61 72 74 5f 73 72 76 } //1 start_srv
		$a_01_2 = {6c 69 64 5f 66 69 6c 65 5f 75 70 64 } //1 lid_file_upd
		$a_01_3 = {6c 6f 63 61 6c 63 66 67 } //1 localcfg
		$a_01_4 = {49 6e 63 6f 72 72 65 63 74 20 72 65 73 70 6f 6e 73 } //1 Incorrect respons
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Tofsee_Z_MTB_2{
	meta:
		description = "Trojan:Win32/Tofsee.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 08 57 8b 7d 10 b1 01 85 ff 74 1d 56 8b 75 0c 2b f0 8a 14 06 32 55 14 88 10 8a d1 02 55 18 f6 d9 00 55 14 40 4f 75 ea 5e 8b 45 08 5f 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Tofsee_Z_MTB_3{
	meta:
		description = "Trojan:Win32/Tofsee.Z!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 53 8a 18 84 db 74 2d 8b d0 2b 54 24 0c 8b 4c 24 0c 84 db 74 12 8a 19 84 db 74 1b 38 1c 0a 75 07 41 80 3c 0a 00 75 ee 80 39 00 74 0a 40 8a 18 42 84 db 75 d9 33 c0 5b c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}