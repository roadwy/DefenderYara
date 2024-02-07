
rule Trojan_BAT_Fsysna_NLF_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.NLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 31 00 00 0a 80 90 01 03 04 20 90 01 03 00 38 90 01 03 ff 20 90 01 03 06 20 90 01 03 86 58 20 90 01 03 fb 61 7e 90 01 03 04 7b 90 01 03 04 61 7e 90 01 03 04 28 90 01 03 06 90 00 } //01 00 
		$a_01_1 = {64 00 6c 00 65 00 78 00 65 00 63 00 } //01 00  dlexec
		$a_01_2 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  ReadProcessMemory
	condition:
		any of ($a_*)
 
}