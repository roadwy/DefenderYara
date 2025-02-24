
rule Trojan_Win32_Fauppod_SAA{
	meta:
		description = "Trojan:Win32/Fauppod.SAA,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 } //10 cmd.exe
		$a_00_1 = {6e 00 65 00 74 00 20 00 75 00 73 00 65 00 } //10 net use
		$a_00_2 = {2e 00 73 00 69 00 40 00 73 00 73 00 6c 00 5c 00 } //10 .si@ssl\
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=30
 
}