
rule Trojan_BAT_Dustylog_A{
	meta:
		description = "Trojan:BAT/Dustylog.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 30 31 35 2d 30 35 2d 31 34 5c 4e 65 44 20 57 6f 72 6d 20 56 65 72 73 69 6f 6e 20 31 20 28 32 30 31 35 2d 30 35 2d 31 35 29 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 6c 6f 67 20 66 69 6c 65 2e 70 64 62 } //1 2015-05-14\NeD Worm Version 1 (2015-05-15)\obj\x86\Debug\log file.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}