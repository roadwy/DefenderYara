
rule Trojan_Win64_Androm_AMX_MTB{
	meta:
		description = "Trojan:Win64/Androm.AMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 05 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 31 37 36 2e 31 31 31 2e 31 37 34 2e 31 34 30 2f 61 70 69 2f 78 6c 6f 61 64 65 72 2e 62 69 6e } //http://176.111.174.140/api/xloader.bin  10
		$a_80_1 = {43 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 4a 6f 68 6e 44 6f } //C:\Documents and Settings\JohnDo  4
		$a_80_2 = {50 72 6f 63 65 73 73 48 61 63 6b 65 72 } //ProcessHacker  2
		$a_80_3 = {78 36 34 64 62 67 } //x64dbg  2
		$a_80_4 = {70 72 6f 63 6d 6f 6e 2e 65 78 65 } //procmon.exe  2
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*4+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=20
 
}