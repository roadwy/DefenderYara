
rule Trojan_Win64_DiskWriter_SP_MTB{
	meta:
		description = "Trojan:Win64/DiskWriter.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 54 24 30 48 8d 0d ?? ?? ?? ?? 89 54 24 28 45 33 c9 ba 00 00 00 10 c7 44 24 20 03 00 00 00 45 8d 41 03 ff 15 ?? ?? ?? ?? 4c 8d 4c 24 40 48 c7 44 24 20 00 00 00 00 48 8b c8 48 8d 54 24 50 41 b8 00 02 00 00 } //5
		$a_81_1 = {4d 42 52 2d 4d 41 4c 57 41 52 45 2d 45 58 41 4d 50 4c 45 53 2e 70 64 62 } //1 MBR-MALWARE-EXAMPLES.pdb
	condition:
		((#a_03_0  & 1)*5+(#a_81_1  & 1)*1) >=6
 
}