
rule Trojan_Win32_NukeSpeed_EC_MTB{
	meta:
		description = "Trojan:Win32/NukeSpeed.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {62 6c 61 63 6b 6c 69 73 74 20 66 6f 75 6e 64 } //1 blacklist found
		$a_81_1 = {63 3a 5c 74 6d 70 5c 62 6c 6b 2e 64 61 74 } //1 c:\tmp\blk.dat
		$a_81_2 = {63 3a 5c 74 6d 70 5c 69 6e 66 6f 2e 64 61 74 } //1 c:\tmp\info.dat
		$a_81_3 = {63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 73 63 6b 2e 64 61 74 } //1 c:\users\public\sck.dat
		$a_81_4 = {63 3a 5c 74 6d 70 5c 5f 44 4d 50 5c 54 4d 50 4c 5f 25 64 5f 25 64 2e 74 6d 70 } //1 c:\tmp\_DMP\TMPL_%d_%d.tmp
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}