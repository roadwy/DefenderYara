
rule Trojan_Win32_TinyADRecon_LKV_MTB{
	meta:
		description = "Trojan:Win32/TinyADRecon.LKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 73 65 72 73 5c 72 61 69 6e 6d 61 6e 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 41 44 52 65 63 6f 6e 5c 54 69 6e 79 41 44 52 65 63 6f 6e 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 54 69 6e 79 41 44 52 65 63 6f 6e 2e 70 64 62 } //00 00  Users\rainman\source\repos\ADRecon\TinyADRecon\obj\Release\TinyADRecon.pdb
	condition:
		any of ($a_*)
 
}