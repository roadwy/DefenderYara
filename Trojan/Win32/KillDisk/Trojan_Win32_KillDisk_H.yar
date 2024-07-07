
rule Trojan_Win32_KillDisk_H{
	meta:
		description = "Trojan:Win32/KillDisk.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 00 42 41 54 90 01 04 40 65 63 68 6f 20 6f 66 66 90 02 08 64 65 6c 20 25 73 79 73 74 65 6d 64 72 69 76 65 25 90 02 10 73 68 75 74 64 6f 77 6e 20 2d 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}