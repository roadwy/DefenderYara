
rule HackTool_Win32_Killgent_DB_MTB{
	meta:
		description = "HackTool:Win32/Killgent.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {5b 2b 5d 20 4c 61 75 6e 63 68 69 6e 67 20 61 74 74 61 63 6b 20 6f 6e 20 6d 73 30 31 } //[+] Launching attack on ms01  1
		$a_80_1 = {5b 2b 5d 20 4d 6f 76 65 64 20 70 6f 6c 69 63 79 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //[+] Moved policy successfully  1
		$a_80_2 = {5b 2b 5d 20 52 65 62 6f 6f 74 65 64 20 74 61 72 67 65 74 } //[+] Rebooted target  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}