
rule Trojan_Win64_FoxChair_B_dha{
	meta:
		description = "Trojan:Win64/FoxChair.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 65 76 63 6f 6e 2e 65 78 65 } //1 devcon.exe
		$a_01_1 = {6b 64 75 2e 65 78 65 } //1 kdu.exe
		$a_01_2 = {56 4d 57 56 4d 43 49 48 4f 53 54 44 45 56 } //1 VMWVMCIHOSTDEV
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}